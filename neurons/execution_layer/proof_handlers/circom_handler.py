import json
import os
import time

# trunk-ignore(bandit/B404)
import subprocess

from typing import TYPE_CHECKING
import bittensor as bt
from constants import FIELD_MODULUS
from utils.pre_flight import LOCAL_SNARKJS_PATH
from execution_layer.proof_handlers.base_handler import ProofSystemHandler
from execution_layer.generic_input import GenericInput

if TYPE_CHECKING:
    from execution_layer.verified_model_session import VerifiedModelSession

LOCAL_SNARKJS_DEFAULT_PATH = "/workspace/project-config/circom/icicle-snark"

class CircomHandler(ProofSystemHandler):
    def gen_input_file(self, session):
        bt.logging.trace("Generating input file")

        data = session.inputs.to_json()

        dir_name = os.path.dirname(session.session_storage.input_path)
        os.makedirs(dir_name, exist_ok=True)

        with open(session.session_storage.input_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        bt.logging.trace(f"Generated input.json with data: {data}")

    def gen_proof(self, session):
        try:
            bt.logging.debug(
                f"Starting proof generation with paths: {session.session_storage.input_path}, "
                f"{session.model.paths.compiled_model}, {session.model.paths.pk}, "
                f"{session.session_storage.proof_path}, {session.session_storage.public_path}"
            )

            proof = self.proof_worker(
                input_path=session.session_storage.input_path,
                circuit_path=session.model.paths.compiled_model,
                pk_path=session.model.paths.pk,
                proof_path=session.session_storage.proof_path,
                public_path=session.session_storage.public_path,
                model_id=session.session_storage.model_id,
            )

            return proof

        except Exception as e:
            bt.logging.error(f"An error occurred during proof generation: {e}")
            raise

    def generate_witness(self, session, return_content: bool = False):
        try:
            bt.logging.debug("Generating witness with optimized methods")
            # Use .wtns for GPU prover compatibility
            witness_wtns = os.path.join(
                session.session_storage.base_path,
                f"witness_{session.model.id}_{session.session_id}.wtns",
            )
            
            # Try optimized witness generation methods in order of preference
            witness_generated = False
            
            # Method 1: Try native C++ witness generation (fastest)
            try:
                witness_generated = self._generate_witness_native(
                    session, witness_wtns
                )
                if witness_generated:
                    bt.logging.info(f"Generated witness using native C++ method: {witness_wtns}")
            except Exception as e:
                bt.logging.debug(f"Native witness generation failed: {e}")
            
            # Method 2: Try ultra-fast witness generation script
            if not witness_generated:
                try:
                    witness_generated = self._generate_witness_ultra_fast(
                        session, witness_wtns
                    )
                    if witness_generated:
                        bt.logging.info(f"Generated witness using ultra-fast method: {witness_wtns}")
                except Exception as e:
                    bt.logging.debug(f"Ultra-fast witness generation failed: {e}")
            
            # Method 3: Try fast witness generation script
            if not witness_generated:
                try:
                    witness_generated = self._generate_witness_fast(
                        session, witness_wtns
                    )
                    if witness_generated:
                        bt.logging.info(f"Generated witness using fast method: {witness_wtns}")
                except Exception as e:
                    bt.logging.debug(f"Fast witness generation failed: {e}")
            
            # Method 4: Fallback to standard snarkjs
            if not witness_generated:
                bt.logging.debug("Falling back to standard snarkjs witness generation")
                command = [
                    LOCAL_SNARKJS_PATH,
                    "wtns",
                    "calculate",
                    session.model.paths.compiled_model,
                    session.session_storage.input_path,
                    witness_wtns,
                ]

                # trunk-ignore(bandit/B603)
                result = subprocess.run(command, check=True, capture_output=True, text=True)

                if result.returncode == 0:
                    witness_generated = True
                    bt.logging.info(f"Generated witness using standard snarkjs: {witness_wtns}")
                else:
                    bt.logging.error(f"Failed to generate witness. Error: {result.stderr}")
                    bt.logging.error(f"Command output: {result.stdout}")
                    raise RuntimeError(f"Witness generation failed: {result.stderr}")
            
            if witness_generated:
                if return_content:
                    json_path = os.path.join(
                        session.session_storage.base_path, "witness.json"
                    )
                    # trunk-ignore(bandit/B603)
                    subprocess.run(
                        [
                            LOCAL_SNARKJS_PATH,
                            "wej",
                            witness_wtns,
                            json_path,
                        ],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    with open(json_path, "r", encoding="utf-8") as f:
                        return json.load(f)
                return witness_wtns
            else:
                raise RuntimeError("All witness generation methods failed")
                
        except subprocess.CalledProcessError as e:
            bt.logging.error(f"Error generating witness: {e}")
            bt.logging.error(f"Command output: {e.stdout}")
            bt.logging.error(f"Command error: {e.stderr}")
            raise RuntimeError(f"Witness generation failed: {str(e)}") from e
        except Exception as e:
            bt.logging.error(f"Unexpected error during witness generation: {e}")
            raise RuntimeError(
                f"Unexpected error during witness generation: {str(e)}"
            ) from e

    def verify_proof(
        self,
        session: "VerifiedModelSession",
        validator_inputs: GenericInput,
        proof: dict,
    ) -> bool:
        try:
            with open(
                session.session_storage.proof_path, "w", encoding="utf-8"
            ) as proof_file:
                json.dump(proof, proof_file)

            public_inputs = session.model.settings["public_inputs"]
            input_order = public_inputs["order"]
            input_sizes = public_inputs["sizes"]

            with open(session.session_storage.input_path, "r", encoding="utf-8") as f:
                updated_public_data = json.load(f)

            validator_json = validator_inputs.to_json()
            current_index = 0

            for input_name in input_order:
                if input_name not in validator_json:
                    current_index += input_sizes[input_name]
                    continue

                value = validator_json[input_name]
                if isinstance(value, list):
                    for i, item in enumerate(value[: input_sizes[input_name]]):
                        updated_public_data[current_index] = str(
                            int(item if item >= 0 else FIELD_MODULUS - abs(item))
                        )
                        current_index += 1
                else:
                    updated_public_data[current_index] = (
                        value if value >= 0 else FIELD_MODULUS - abs(value)
                    )
                    current_index += 1

            with open(
                session.session_storage.public_path, "w", encoding="utf-8"
            ) as public_file:
                json.dump(updated_public_data, public_file)

            result = subprocess.run(
                [
                    LOCAL_SNARKJS_PATH,
                    "g16v",
                    session.model.paths.vk,
                    session.session_storage.public_path,
                    session.session_storage.proof_path,
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            return "OK!" in result.stdout

        except Exception as e:
            bt.logging.error(f"Proof verification failed: {str(e)}")
            return False

    @staticmethod
    def proof_worker(
        input_path, circuit_path, pk_path, proof_path, public_path, model_id
    ) -> tuple[str, str]:
        try:
            # start_time = time.time()
            size_mapping = {
                "1550853037e01d93c0831e2a4f80de7811b1c6780fb36b3cee89f4ba524df1be": 1024,
                "4a87c995300f4e9ad9add9d5b800eb93bb3ecd3f9459b617f9924a211407a88c": 256
            }

            transform_size = size_mapping.get(model_id, 1024)

            input_path_transformed = input_path.replace("input_", "input_transformed_")

            # transform_time = time.time() - start_time
            # bt.logging.info(f"Transform input time 1: {transform_time}s")

            # start_time1 = time.time()

            transfer_result = subprocess.run(
                [
                    "python3",
                    "./execution_layer/transform_input.py",
                    input_path,
                    input_path_transformed,
                    str(transform_size)
                ],
            )
            if transfer_result.returncode != 0:
                bt.logging.error(f"Failed to transfer input file: {transfer_result.stderr}")
                raise RuntimeError(f"Failed to transfer input file: {transfer_result.stderr}")

            # transfer_time = time.time() - start_time1
            # bt.logging.info(f"Transfer input time 2: {transfer_time}s")
            # start_time2 = time.time()

            graph_mapping = {
                "1550853037e01d93c0831e2a4f80de7811b1c6780fb36b3cee89f4ba524df1be": "./graph_1550.bin",
                "4a87c995300f4e9ad9add9d5b800eb93bb3ecd3f9459b617f9924a211407a88c": "./graph_4a87.bin"
            }

            graph_path = graph_mapping.get(model_id, "./graph_1550.bin")


            # transfer_time1 = time.time() - start_time2
            # bt.logging.info(f"Transfer input time 3: {transfer_time1}s")
            # start_time3 = time.time()

            # Prepare the request payload
            payload = {
                "input_file": input_path_transformed,
                "circuit_file": graph_path,
                "zkey_file": pk_path,
                "proof_output": proof_path,
                "public_output": public_path,
                "device": "CUDA"
            }

            # Map model IDs to their corresponding server ports
            model_port_mapping = {
                "1550853037e01d93c0831e2a4f80de7811b1c6780fb36b3cee89f4ba524df1be": 8107,
                "4a87c995300f4e9ad9add9d5b800eb93bb3ecd3f9459b617f9924a211407a88c": 8109
            }
            
            # Get the port for the current model ID
            port = model_port_mapping.get(model_id, 8107)  # Default to 8106 if model ID not found

            # bt.logging.info(f"Sending request to ICICLE service time: {time.time() - start_time3}s")
            # start_time4 = time.time()

            # Make HTTP request to ICICLE service
            result = subprocess.run(
                [
                    "curl",
                    "-X", "POST",
                    f"http://127.0.0.1:{port}/prove",
                    "-H", "Content-Type: application/json",
                    "-d", json.dumps(payload)
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            bt.logging.info(f"result: {result.stdout}")

            # proof_time = time.time() - start_time4
            # bt.logging.info(f"Proof generation time: {proof_time}s")

            bt.logging.debug(f"Proof generated: {proof_path}")
            bt.logging.trace(f"Proof generation stdout: {result.stdout}")
            bt.logging.trace(f"Proof generation stderr: {result.stderr}")
            proof = None
            with open(proof_path, "r", encoding="utf-8") as proof_file:
                proof = proof_file.read()
            with open(public_path, "r", encoding="utf-8") as public_file:
                public_data = public_file.read()
            return proof, public_data
        except subprocess.CalledProcessError as e:
            try:
                bt.logging.info("Starting proof generation with exception...")
                graph_mapping = {
                    "1550853037e01d93c0831e2a4f80de7811b1c6780fb36b3cee89f4ba524df1be": "/workspace/project-config/circom/graph_1550.bin",
                    "4a87c995300f4e9ad9add9d5b800eb93bb3ecd3f9459b617f9924a211407a88c": "/workspace/project-config/circom/graph_4a87.bin"
                }

                graph_path = graph_mapping.get(model_id, "/workspace/project-config/circom/graph_1550.bin")

                result = subprocess.run(
                    [
                        LOCAL_SNARKJS_DEFAULT_PATH,
                        "prove-from-circuit",
                        "--circuit", graph_path,
                        "--inputs", input_path_transformed,
                        "--zkey", pk_path,
                        "--proof", proof_path,
                        "--public", public_path,
                        "--device", "CUDA"
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )

                bt.logging.debug(f"Proof generated with exception: {proof_path}")
                bt.logging.trace(f"Proof generation stdout with exception: {result.stdout}")
                bt.logging.trace(f"Proof generation stderr with exception: {result.stderr}")
                proof = None
                with open(proof_path, "r", encoding="utf-8") as proof_file:
                    proof = proof_file.read()
                with open(public_path, "r", encoding="utf-8") as public_file:
                    public_data = public_file.read()
                return proof, public_data
            except Exception as e:
                bt.logging.error(f"Error generating proof with exception: {e}")
                bt.logging.error(f"Proof generation stdout: {e.stdout}")
                bt.logging.error(f"Proof generation stderr: {e.stderr}")
                raise

    @staticmethod
    def _proof_worker_snarkjs_fork(
        input_path, circuit_path, pk_path, proof_path, public_path, base_path, snarkjs_fork_path
    ) -> tuple[str, str]:
        """Use snarkjs-fork wrapper for GPU-accelerated proof generation."""
        try:
            # Extract circuit type from model path (assuming model_id format)
            circuit_type = os.path.basename(os.path.dirname(circuit_path)).replace("model_", "circuit_")
            
            # Set up environment variables for snarkjs-fork with performance optimizations
            env = os.environ.copy()
            env.update({
                "CIRCUIT_TYPE": circuit_type,
                "INPUT_JSON": input_path,
                "ZKEY_PATH": pk_path,
                "OUTDIR": base_path,
                "PROVER_BIN": os.environ.get("PROVER_BIN", "icicle-snark"),
                "CUDA_DEVICE": os.environ.get("CUDA_DEVICE", "0"),
                # Performance optimizations
                "NODE_OPTIONS": "--max-old-space-size=8192",
                "CUDA_CACHE_DISABLE": "0",
                "CUDA_CACHE_MAXSIZE": "2147483648",
                "UV_THREADPOOL_SIZE": "1",
                "OMP_NUM_THREADS": "1",
            })
            
            # Try ultra-optimized script first, then ultra-fast, then regular script
            ultra_optimized_script = os.path.join(snarkjs_fork_path, "scripts", "ultra_optimized_proof.sh")
            ultra_fast_script = os.path.join(snarkjs_fork_path, "scripts", "ultra_fast_proof.sh")
            run_proof_script = os.path.join(snarkjs_fork_path, "scripts", "run_proof.sh")
            
            if os.path.exists(ultra_optimized_script):
                script_to_use = ultra_optimized_script
                bt.logging.debug("Using ultra-optimized proof generation script")
            elif os.path.exists(ultra_fast_script):
                script_to_use = ultra_fast_script
                bt.logging.debug("Using ultra-fast proof generation script")
            else:
                script_to_use = run_proof_script
                bt.logging.debug("Using standard proof generation script")
            
            if not os.path.exists(script_to_use):
                raise FileNotFoundError(f"snarkjs-fork script not found: {script_to_use}")
            
            # Make script executable
            os.chmod(script_to_use, 0o755)
            
            # Set additional performance optimizations
            env.update({
                "CIRCUIT_TYPE": circuit_type,
                "INPUT_JSON": input_path,
                "ZKEY_PATH": pk_path,
                "OUTDIR": base_path,
                "PROVER_BIN": env["PROVER_BIN"],
                "CUDA_DEVICE": env["CUDA_DEVICE"],
                # Additional optimizations
                "NODE_OPTIONS": "--max-old-space-size=8192 --optimize-for-size",
                "CUDA_CACHE_DISABLE": "0",
                "CUDA_CACHE_MAXSIZE": "2147483648",
                "UV_THREADPOOL_SIZE": "1",
                "OMP_NUM_THREADS": "1",
                "NODE_ENV": "production"
            })
            
            # trunk-ignore(bandit/B603)
            result = subprocess.run(
                [script_to_use, circuit_type, input_path, pk_path, base_path, 
                 env["PROVER_BIN"], env["CUDA_DEVICE"]],
                env=env,
                check=True,
                capture_output=True,
                text=True,
                cwd=snarkjs_fork_path,
                timeout=120  # Increased timeout for ultra-optimized script
            )
            
            bt.logging.debug(f"snarkjs-fork completed: {result.stdout}")
            bt.logging.trace(f"snarkjs-fork stderr: {result.stderr}")
            
            # Read generated proof and public files
            with open(proof_path, "r", encoding="utf-8") as proof_file:
                proof = proof_file.read()
            with open(public_path, "r", encoding="utf-8") as public_file:
                public_data = public_file.read()
            
            return proof, public_data
            
        except subprocess.TimeoutExpired:
            bt.logging.warning("snarkjs-fork timed out, falling back to direct method")
            return CircomHandler._proof_worker_direct(
                input_path, circuit_path, pk_path, proof_path, public_path, base_path
            )
        except Exception as e:
            bt.logging.warning(f"snarkjs-fork failed, falling back to direct method: {e}")
            return CircomHandler._proof_worker_direct(
                input_path, circuit_path, pk_path, proof_path, public_path, base_path
            )

    @staticmethod
    def _proof_worker_direct(
        input_path, circuit_path, pk_path, proof_path, public_path, base_path
    ) -> tuple[str, str]:
        """Direct GPU prover approach (fallback) with performance optimizations."""
        try:
            bt.logging.debug("Starting direct proof generation with performance optimizations")
            total_start = time.time()
            # 1) Ensure witness exists (.wtns) with caching
            witness_wtns = os.path.join(
                base_path,
                f"witness_{os.path.basename(proof_path).replace('proof_', '').replace('.json','')}.wtns",
            )
            
            # Check if witness exists and is recent (within 1 minute)
            witness_exists = False
            if os.path.exists(witness_wtns):
                witness_stat = os.stat(witness_wtns)
                input_stat = os.stat(input_path)
                # Use witness if it's newer than input or within 1 minute
                if witness_stat.st_mtime >= input_stat.st_mtime or (time.time() - witness_stat.st_mtime) < 60:
                    witness_exists = True
                    bt.logging.debug(f"Reusing existing witness: {witness_wtns}")
            
            if not witness_exists:
                # Generate witness if missing or stale
                bt.logging.debug("Generating fresh witness")
                witness_start = time.time()
                
                # Try optimized witness generation methods in order of preference
                try:
                    # Method 1: Try native C++ witness generation (fastest)
                    snarkjs_fork_path = os.environ.get("SNARKJS_FORK_PATH", "")
                    if snarkjs_fork_path:
                        native_witness = os.path.join(snarkjs_fork_path, "scripts", "native_witness.js")
                        if os.path.exists(native_witness):
                            bt.logging.debug("Using native C++ witness generation")
                            env_native = os.environ.copy()
                            env_native.update({
                                "NODE_OPTIONS": "--max-old-space-size=8192",
                                "UV_THREADPOOL_SIZE": "1",
                                "NODE_ENV": "production"
                            })
                            
                            circuit_dir = os.path.dirname(circuit_path)
                            result = subprocess.run(
                                ["node", native_witness, circuit_dir, input_path, witness_wtns],
                                check=True,
                                capture_output=True,
                                text=True,
                                env=env_native,
                                timeout=30
                            )
                            witness_time = time.time() - witness_start
                            bt.logging.debug(f"Native witness generated in {witness_time:.3f}s")
                            witness_exists = True
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
                    bt.logging.debug(f"Native witness failed: {e}, trying ultra-fast method")
                
                if not witness_exists:
                    try:
                        # Method 2: Try ultra-fast witness generation
                        snarkjs_fork_path = os.environ.get("SNARKJS_FORK_PATH", "")
                        if snarkjs_fork_path:
                            ultra_fast_witness = os.path.join(snarkjs_fork_path, "scripts", "ultra_fast_witness.js")
                            if os.path.exists(ultra_fast_witness):
                                bt.logging.debug("Using ultra-fast witness generation")
                                env_ultra = os.environ.copy()
                                env_ultra.update({
                                    "NODE_OPTIONS": "--max-old-space-size=8192",
                                    "UV_THREADPOOL_SIZE": "1",
                                    "NODE_ENV": "production"
                                })
                                
                                result = subprocess.run(
                                    ["node", ultra_fast_witness, circuit_path, input_path, witness_wtns],
                                    check=True,
                                    capture_output=True,
                                    text=True,
                                    env=env_ultra,
                                    timeout=30
                                )
                                witness_time = time.time() - witness_start
                                bt.logging.debug(f"Ultra-fast witness generated in {witness_time:.3f}s")
                                witness_exists = True
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
                        bt.logging.debug(f"Ultra-fast witness failed: {e}, trying fast method")
                
                if not witness_exists:
                    try:
                        # Method 3: Try fast witness generation
                        snarkjs_fork_path = os.environ.get("SNARKJS_FORK_PATH", "")
                        if snarkjs_fork_path:
                            fast_witness = os.path.join(snarkjs_fork_path, "scripts", "fast_witness.js")
                            if os.path.exists(fast_witness):
                                bt.logging.debug("Using fast witness generation")
                                env_fast = os.environ.copy()
                                env_fast.update({
                                    "NODE_OPTIONS": "--max-old-space-size=8192",
                                    "UV_THREADPOOL_SIZE": "1",
                                    "NODE_ENV": "production"
                                })
                                
                                result = subprocess.run(
                                    ["node", fast_witness, circuit_path, input_path, witness_wtns],
                                    check=True,
                                    capture_output=True,
                                    text=True,
                                    env=env_fast,
                                    timeout=60
                                )
                                witness_time = time.time() - witness_start
                                bt.logging.debug(f"Fast witness generated in {witness_time:.3f}s")
                                witness_exists = True
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
                        bt.logging.debug(f"Fast witness failed: {e}, trying standard method")
                
                if not witness_exists:
                    # Try optimized witness generation first
                    try:
                        # Use snarkjs with optimized settings
                        env = os.environ.copy()
                        env.update({
                            "NODE_OPTIONS": "--max-old-space-size=8192",
                            "UV_THREADPOOL_SIZE": "1",  # Single thread for Node.js
                            "NODE_ENV": "production"
                        })
                        
                        # trunk-ignore(bandit/B603)
                        result = subprocess.run(
                            [
                                LOCAL_SNARKJS_PATH,
                                "wtns",
                                "calculate",
                                circuit_path,
                                input_path,
                                witness_wtns,
                            ],
                            check=True,
                            capture_output=True,
                            text=True,
                            env=env,
                            timeout=60  # 60 second timeout
                        )
                        witness_time = time.time() - witness_start
                        bt.logging.debug(f"Witness generated in {witness_time:.3f}s")
                    except subprocess.TimeoutExpired:
                        bt.logging.warning("Witness generation timed out, retrying with basic method")
                        # trunk-ignore(bandit/B603)
                        subprocess.run(
                            [
                                LOCAL_SNARKJS_PATH,
                                "wtns",
                                "calculate",
                                circuit_path,
                                input_path,
                                witness_wtns,
                            ],
                            check=True,
                            capture_output=True,
                            text=True,
                        )
                    except subprocess.CalledProcessError as e:
                        bt.logging.error(f"Witness generation failed with exit code {e.returncode}")
                        bt.logging.error(f"STDOUT: {e.stdout}")
                        bt.logging.error(f"STDERR: {e.stderr}")
                        
                        # Check if input file exists and is valid
                        if not os.path.exists(input_path):
                            raise RuntimeError(f"Input file not found: {input_path}")
                        
                        # Check if circuit file exists
                        if not os.path.exists(circuit_path):
                            raise RuntimeError(f"Circuit file not found: {circuit_path}")
                        
                        # Try with minimal memory settings
                        bt.logging.warning("Retrying with minimal memory settings")
                        env_minimal = os.environ.copy()
                        env_minimal.update({
                            "NODE_OPTIONS": "--max-old-space-size=2048",
                            "UV_THREADPOOL_SIZE": "1"
                        })
                        
                        try:
                            # trunk-ignore(bandit/B603)
                            subprocess.run(
                                [
                                    LOCAL_SNARKJS_PATH,
                                    "wtns",
                                    "calculate",
                                    circuit_path,
                                    input_path,
                                    witness_wtns,
                                ],
                                check=True,
                                capture_output=True,
                                text=True,
                                env=env_minimal,
                                timeout=120  # Longer timeout for minimal settings
                            )
                        except subprocess.CalledProcessError as e2:
                            bt.logging.error(f"Witness generation failed again with exit code {e2.returncode}")
                            bt.logging.error(f"STDOUT: {e2.stdout}")
                            bt.logging.error(f"STDERR: {e2.stderr}")
                            
                            # Try to get more detailed error information
                            bt.logging.error(f"Input file size: {os.path.getsize(input_path) if os.path.exists(input_path) else 'N/A'}")
                            bt.logging.error(f"Circuit file size: {os.path.getsize(circuit_path) if os.path.exists(circuit_path) else 'N/A'}")
                            
                            # Try to validate input JSON
                            try:
                                with open(input_path, 'r') as f:
                                    input_data = json.load(f)
                                    bt.logging.debug(f"Input data structure: {list(input_data.keys()) if isinstance(input_data, dict) else 'Not a dict'}")
                            except Exception as json_err:
                                bt.logging.error(f"Input JSON validation failed: {json_err}")
                            
                            raise RuntimeError(f"Witness generation failed after retries: {e2.stderr}") from e2

            # 2) Run GPU prover using the exact icicle-snark command format
            import shutil
            prover_bin = os.environ.get("PROVER_BIN", "icicle-snark")
            prover_path = os.environ.get("ICICLE_SNARK_PATH") or prover_bin
            # Resolve full path if needed
            resolved_prover = shutil.which(prover_path) or prover_path

            # Use printf to pipe the command to icicle-snark (matching your format)
            pipe_cmd = (
                f"printf 'prove --witness {witness_wtns} --zkey {pk_path} --proof {proof_path} --public {public_path} --device CUDA\\nexit\\n' | {resolved_prover}"
            )
            try:
                # trunk-ignore(bandit/B603)
                result = subprocess.run(
                    ["bash", "-c", pipe_cmd], check=True, capture_output=True, text=True
                )
                bt.logging.debug(f"Proof generated by {resolved_prover}: {proof_path}")
                bt.logging.trace(f"GPU prover stdout: {result.stdout}")
                bt.logging.trace(f"GPU prover stderr: {result.stderr}")
            except subprocess.CalledProcessError as gpu_err:
                # If command not found (127) or other failure, try direct-args mode
                bt.logging.warning(
                    f"GPU prover '{resolved_prover}' pipe mode failed (exit {gpu_err.returncode}), trying direct args"
                )
                direct_cmd = [
                    resolved_prover,
                    "prove",
                    "--zkey",
                    pk_path,
                    "--witness",
                    witness_wtns,
                    "--proof",
                    proof_path,
                    "--public",
                    public_path,
                    "--device",
                    "CUDA",
                ]
                try:
                    # trunk-ignore(bandit/B603)
                    result = subprocess.run(
                        direct_cmd, check=True, capture_output=True, text=True
                    )
                    bt.logging.debug(
                        f"Proof generated by {resolved_prover} (direct args): {proof_path}"
                    )
                    bt.logging.trace(f"GPU prover stdout: {result.stdout}")
                    bt.logging.trace(f"GPU prover stderr: {result.stderr}")
                except subprocess.CalledProcessError as gpu_err2:
                    bt.logging.warning(
                        f"GPU prover '{resolved_prover}' failed, falling back to snarkjs g16f: {gpu_err2}"
                    )
                bt.logging.warning(
                    "Set environment variable PROVER_BIN or ICICLE_SNARK_PATH to the absolute path of icicle-snark if not in PATH."
                )
                # Fallback to snarkjs flow to avoid request failure
                # trunk-ignore(bandit/B603)
                result = subprocess.run(
                    [
                        LOCAL_SNARKJS_PATH,
                        "g16f",
                        input_path,
                        circuit_path,
                        pk_path,
                        proof_path,
                        public_path,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                bt.logging.debug(f"Proof generated by snarkjs fallback: {proof_path}")
                bt.logging.trace(f"snarkjs stdout: {result.stdout}")
                bt.logging.trace(f"snarkjs stderr: {result.stderr}")
            
            proof = None
            with open(proof_path, "r", encoding="utf-8") as proof_file:
                proof = proof_file.read()
            with open(public_path, "r", encoding="utf-8") as public_file:
                public_data = public_file.read()
            
            total_time = time.time() - total_start
            bt.logging.debug(f"Direct proof generation completed in {total_time:.3f}s")
            
            return proof, public_data
        except subprocess.CalledProcessError as e:
            bt.logging.error(f"Error generating proof: {e}")
            bt.logging.error(f"Proof generation stdout: {e.stdout}")
            bt.logging.error(f"Proof generation stderr: {e.stderr}")
            raise

    def _generate_witness_native(self, session, witness_wtns: str) -> bool:
        """Generate witness using native C++ implementation (fastest method)."""
        try:
            # Check if snarkjs-fork is available
            snarkjs_fork_path = os.environ.get("SNARKJS_FORK_PATH", "")
            if not snarkjs_fork_path:
                # Auto-detect snarkjs-fork path
                possible_paths = [
                    "/workspace/snarkjs-fork",
                    "/workspace/omron-icicle-snark/snarkjs-fork", 
                    os.path.join(os.path.dirname(__file__), "..", "..", "..", "snarkjs-fork"),
                    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "snarkjs-fork"),
                    os.path.join(os.getcwd(), "snarkjs-fork"),
                    os.path.abspath("snarkjs-fork"),
                ]
                for path in possible_paths:
                    if os.path.exists(os.path.join(path, "scripts", "native_witness.js")):
                        snarkjs_fork_path = os.path.abspath(path)
                        break
            
            if not snarkjs_fork_path or not os.path.exists(snarkjs_fork_path):
                return False
            
            # Check if native module is available
            native_witness_script = os.path.join(snarkjs_fork_path, "scripts", "native_witness.js")
            if not os.path.exists(native_witness_script):
                return False
            
            # Get circuit directory (should contain .dat file)
            circuit_dir = os.path.dirname(session.model.paths.compiled_model)
            
            # Set optimized environment
            env = os.environ.copy()
            env.update({
                "NODE_OPTIONS": "--max-old-space-size=8192",
                "UV_THREADPOOL_SIZE": "1",
                "NODE_ENV": "production"
            })
            
            # Run native witness generation
            result = subprocess.run(
                ["node", native_witness_script, circuit_dir, session.session_storage.input_path, witness_wtns],
                check=True,
                capture_output=True,
                text=True,
                env=env,
                timeout=30
            )
            
            return os.path.exists(witness_wtns) and os.path.getsize(witness_wtns) > 0
            
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            bt.logging.debug(f"Native witness generation failed: {e}")
            return False
        except Exception as e:
            bt.logging.debug(f"Native witness generation error: {e}")
            return False

    def _generate_witness_ultra_fast(self, session, witness_wtns: str) -> bool:
        """Generate witness using ultra-fast witness generation script."""
        try:
            # Check if snarkjs-fork is available
            snarkjs_fork_path = os.environ.get("SNARKJS_FORK_PATH", "")
            if not snarkjs_fork_path:
                # Auto-detect snarkjs-fork path
                possible_paths = [
                    "/workspace/snarkjs-fork",
                    "/workspace/omron-icicle-snark/snarkjs-fork", 
                    os.path.join(os.path.dirname(__file__), "..", "..", "..", "snarkjs-fork"),
                    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "snarkjs-fork"),
                    os.path.join(os.getcwd(), "snarkjs-fork"),
                    os.path.abspath("snarkjs-fork"),
                ]
                for path in possible_paths:
                    if os.path.exists(os.path.join(path, "scripts", "ultra_fast_witness.js")):
                        snarkjs_fork_path = os.path.abspath(path)
                        break
            
            if not snarkjs_fork_path or not os.path.exists(snarkjs_fork_path):
                return False
            
            ultra_fast_script = os.path.join(snarkjs_fork_path, "scripts", "ultra_fast_witness.js")
            if not os.path.exists(ultra_fast_script):
                return False
            
            # Set optimized environment
            env = os.environ.copy()
            env.update({
                "NODE_OPTIONS": "--max-old-space-size=8192",
                "UV_THREADPOOL_SIZE": "1",
                "NODE_ENV": "production"
            })
            
            # Run ultra-fast witness generation
            result = subprocess.run(
                ["node", ultra_fast_script, session.model.paths.compiled_model, session.session_storage.input_path, witness_wtns],
                check=True,
                capture_output=True,
                text=True,
                env=env,
                timeout=30
            )
            
            return os.path.exists(witness_wtns) and os.path.getsize(witness_wtns) > 0
            
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            bt.logging.debug(f"Ultra-fast witness generation failed: {e}")
            return False
        except Exception as e:
            bt.logging.debug(f"Ultra-fast witness generation error: {e}")
            return False

    def _generate_witness_fast(self, session, witness_wtns: str) -> bool:
        """Generate witness using fast witness generation script."""
        try:
            # Check if snarkjs-fork is available
            snarkjs_fork_path = os.environ.get("SNARKJS_FORK_PATH", "")
            if not snarkjs_fork_path:
                # Auto-detect snarkjs-fork path
                possible_paths = [
                    "/workspace/snarkjs-fork",
                    "/workspace/omron-icicle-snark/snarkjs-fork", 
                    os.path.join(os.path.dirname(__file__), "..", "..", "..", "snarkjs-fork"),
                    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "snarkjs-fork"),
                    os.path.join(os.getcwd(), "snarkjs-fork"),
                    os.path.abspath("snarkjs-fork"),
                ]
                for path in possible_paths:
                    if os.path.exists(os.path.join(path, "scripts", "fast_witness.js")):
                        snarkjs_fork_path = os.path.abspath(path)
                        break
            
            if not snarkjs_fork_path or not os.path.exists(snarkjs_fork_path):
                return False
            
            fast_script = os.path.join(snarkjs_fork_path, "scripts", "fast_witness.js")
            if not os.path.exists(fast_script):
                return False
            
            # Set optimized environment
            env = os.environ.copy()
            env.update({
                "NODE_OPTIONS": "--max-old-space-size=8192",
                "UV_THREADPOOL_SIZE": "1",
                "NODE_ENV": "production"
            })
            
            # Run fast witness generation
            result = subprocess.run(
                ["node", fast_script, session.model.paths.compiled_model, session.session_storage.input_path, witness_wtns],
                check=True,
                capture_output=True,
                text=True,
                env=env,
                timeout=60
            )
            
            return os.path.exists(witness_wtns) and os.path.getsize(witness_wtns) > 0
            
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            bt.logging.debug(f"Fast witness generation failed: {e}")
            return False
        except Exception as e:
            bt.logging.debug(f"Fast witness generation error: {e}")
            return False

    @staticmethod
    def aggregate_proofs(
        session: "VerifiedModelSession", proofs: list[str]
    ) -> tuple[str, float]:
        raise NotImplementedError(
            "Aggregation of proofs is not implemented for CircomHandler"
        )
