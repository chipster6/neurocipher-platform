"""
GPU Detection and Resource Management
Automatically detects available GPU resources and configures inference accordingly
"""

import logging
import torch
import platform
import subprocess
import psutil
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class InferenceDevice(str, Enum):
    """Available inference devices"""
    CPU = "cpu"
    CUDA = "cuda"
    MPS = "mps"  # Apple Metal Performance Shaders
    OPENCL = "opencl"

@dataclass
class GPUInfo:
    """GPU information structure"""
    device_id: int
    name: str
    memory_total: int  # MB
    memory_free: int   # MB
    compute_capability: Optional[Tuple[int, int]]
    device_type: InferenceDevice
    is_available: bool
    performance_score: int  # 0-100

@dataclass
class InferenceConfig:
    """Inference configuration based on detected hardware"""
    device: InferenceDevice
    device_id: int
    max_batch_size: int
    max_sequence_length: int
    use_quantization: bool
    use_mixed_precision: bool
    gpu_memory_fraction: float
    cpu_threads: int

class GPUDetectionManager:
    """
    Detects and manages GPU resources for optimal inference performance
    Provides automatic fallback from GPU to CPU when needed
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.detected_gpus: List[GPUInfo] = []
        self.optimal_device: Optional[InferenceDevice] = None
        self.inference_config: Optional[InferenceConfig] = None
        self._detection_cache = {}
        
    async def detect_hardware(self) -> Dict[str, Any]:
        """
        Detect all available inference hardware and capabilities
        
        Returns:
            Dictionary containing hardware detection results
        """
        try:
            logger.info("Detecting available inference hardware...")
            
            detection_results = {
                "cpu_info": await self._detect_cpu_capabilities(),
                "gpu_info": await self._detect_gpu_capabilities(),
                "memory_info": await self._detect_memory_capabilities(),
                "optimal_config": None
            }
            
            # Determine optimal inference configuration
            self.inference_config = await self._determine_optimal_config(detection_results)
            detection_results["optimal_config"] = self.inference_config
            
            logger.info(f"Hardware detection completed. Optimal device: {self.inference_config.device}")
            return detection_results
            
        except Exception as e:
            logger.error(f"Hardware detection failed: {e}")
            # Fallback to CPU-only configuration
            self.inference_config = self._get_cpu_fallback_config()
            return {
                "cpu_info": {"cores": psutil.cpu_count(), "available": True},
                "gpu_info": {"available_gpus": [], "cuda_available": False},
                "memory_info": {"total_ram": psutil.virtual_memory().total // (1024**3)},
                "optimal_config": self.inference_config,
                "detection_error": str(e)
            }
    
    async def _detect_cpu_capabilities(self) -> Dict[str, Any]:
        """Detect CPU capabilities and performance characteristics"""
        try:
            cpu_info = {
                "cores": psutil.cpu_count(logical=False),
                "logical_cores": psutil.cpu_count(logical=True),
                "frequency": psutil.cpu_freq().max if psutil.cpu_freq() else 0,
                "architecture": platform.machine(),
                "available": True,
                "performance_score": 0
            }
            
            # Calculate CPU performance score
            base_score = min(cpu_info["cores"] * 10, 50)  # Up to 50 points for cores
            freq_score = min((cpu_info["frequency"] / 1000) * 5, 30) if cpu_info["frequency"] else 0  # Up to 30 for frequency
            arch_score = 20 if cpu_info["architecture"] in ["x86_64", "arm64"] else 10  # Architecture bonus
            
            cpu_info["performance_score"] = int(base_score + freq_score + arch_score)
            
            logger.info(f"CPU detected: {cpu_info['cores']} cores, {cpu_info['frequency']}MHz, score: {cpu_info['performance_score']}")
            return cpu_info
            
        except Exception as e:
            logger.error(f"CPU detection failed: {e}")
            return {"cores": 1, "available": True, "performance_score": 20}
    
    async def _detect_gpu_capabilities(self) -> Dict[str, Any]:
        """Detect GPU capabilities and available devices"""
        gpu_info = {
            "available_gpus": [],
            "cuda_available": False,
            "mps_available": False,
            "best_gpu": None,
            "total_gpu_memory": 0
        }
        
        try:
            # Detect CUDA GPUs
            if torch.cuda.is_available():
                gpu_info["cuda_available"] = True
                cuda_gpus = await self._detect_cuda_gpus()
                gpu_info["available_gpus"].extend(cuda_gpus)
                logger.info(f"CUDA detected: {len(cuda_gpus)} GPU(s)")
            
            # Detect Apple Metal Performance Shaders (MPS)
            if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
                gpu_info["mps_available"] = True
                mps_gpu = await self._detect_mps_gpu()
                if mps_gpu:
                    gpu_info["available_gpus"].append(mps_gpu)
                logger.info("Apple MPS detected")
            
            # Find best GPU
            if gpu_info["available_gpus"]:
                gpu_info["best_gpu"] = max(gpu_info["available_gpus"], key=lambda x: x.performance_score)
                gpu_info["total_gpu_memory"] = sum(gpu.memory_total for gpu in gpu_info["available_gpus"])
                
                logger.info(f"Best GPU: {gpu_info['best_gpu'].name} with {gpu_info['best_gpu'].memory_total}MB")
            
            self.detected_gpus = gpu_info["available_gpus"]
            return gpu_info
            
        except Exception as e:
            logger.error(f"GPU detection failed: {e}")
            return gpu_info
    
    async def _detect_cuda_gpus(self) -> List[GPUInfo]:
        """Detect CUDA-capable GPUs"""
        cuda_gpus = []
        
        try:
            device_count = torch.cuda.device_count()
            
            for i in range(device_count):
                try:
                    props = torch.cuda.get_device_properties(i)
                    memory_total = props.total_memory // (1024 * 1024)  # Convert to MB
                    memory_free = memory_total - (torch.cuda.memory_allocated(i) // (1024 * 1024))
                    
                    # Calculate performance score based on specifications
                    compute_score = (props.major * 10 + props.minor) * 5  # Compute capability
                    memory_score = min(memory_total // 1024, 50)  # Memory in GB, up to 50 points
                    multiprocessor_score = min(props.multi_processor_count, 30)  # MP count, up to 30 points
                    
                    performance_score = min(compute_score + memory_score + multiprocessor_score, 100)
                    
                    gpu_info = GPUInfo(
                        device_id=i,
                        name=props.name,
                        memory_total=memory_total,
                        memory_free=memory_free,
                        compute_capability=(props.major, props.minor),
                        device_type=InferenceDevice.CUDA,
                        is_available=True,
                        performance_score=performance_score
                    )
                    
                    cuda_gpus.append(gpu_info)
                    logger.info(f"CUDA GPU {i}: {props.name}, {memory_total}MB, CC {props.major}.{props.minor}")
                    
                except Exception as e:
                    logger.error(f"Failed to query CUDA device {i}: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"CUDA detection failed: {e}")
        
        return cuda_gpus
    
    async def _detect_mps_gpu(self) -> Optional[GPUInfo]:
        """Detect Apple Metal Performance Shaders GPU"""
        try:
            # MPS doesn't provide detailed memory info, so we estimate
            total_memory = 8192  # Estimate 8GB for typical Apple Silicon
            
            gpu_info = GPUInfo(
                device_id=0,
                name="Apple Silicon GPU",
                memory_total=total_memory,
                memory_free=total_memory // 2,  # Estimate 50% free
                compute_capability=None,
                device_type=InferenceDevice.MPS,
                is_available=True,
                performance_score=75  # Good performance score for Apple Silicon
            )
            
            logger.info("Apple MPS GPU detected")
            return gpu_info
            
        except Exception as e:
            logger.error(f"MPS detection failed: {e}")
            return None
    
    async def _detect_memory_capabilities(self) -> Dict[str, Any]:
        """Detect system memory capabilities"""
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            memory_info = {
                "total_ram": memory.total // (1024**3),  # GB
                "available_ram": memory.available // (1024**3),  # GB
                "total_swap": swap.total // (1024**3),  # GB
                "memory_pressure": memory.percent,
                "recommended_batch_size": await self._calculate_recommended_batch_size(memory.available)
            }
            
            logger.info(f"System memory: {memory_info['total_ram']}GB total, {memory_info['available_ram']}GB available")
            return memory_info
            
        except Exception as e:
            logger.error(f"Memory detection failed: {e}")
            return {"total_ram": 8, "available_ram": 4, "recommended_batch_size": 1}
    
    async def _calculate_recommended_batch_size(self, available_memory: int) -> int:
        """Calculate recommended batch size based on available memory"""
        # Rule of thumb: 1GB RAM per batch item for transformer models
        gb_available = available_memory // (1024**3)
        
        if gb_available >= 16:
            return 8
        elif gb_available >= 8:
            return 4
        elif gb_available >= 4:
            return 2
        else:
            return 1
    
    async def _determine_optimal_config(self, detection_results: Dict[str, Any]) -> InferenceConfig:
        """Determine optimal inference configuration based on detected hardware"""
        try:
            gpu_info = detection_results["gpu_info"]
            cpu_info = detection_results["cpu_info"]
            memory_info = detection_results["memory_info"]
            
            # Choose best available device
            if gpu_info["available_gpus"]:
                best_gpu = gpu_info["best_gpu"]
                device = best_gpu.device_type
                device_id = best_gpu.device_id
                
                # GPU-optimized configuration
                config = InferenceConfig(
                    device=device,
                    device_id=device_id,
                    max_batch_size=min(8, memory_info["recommended_batch_size"]),
                    max_sequence_length=4096 if best_gpu.memory_total > 8000 else 2048,
                    use_quantization=best_gpu.memory_total < 12000,  # Use quantization for <12GB VRAM
                    use_mixed_precision=True,
                    gpu_memory_fraction=0.8,
                    cpu_threads=cpu_info["cores"]
                )
                
                logger.info(f"GPU configuration: {device} device {device_id}, batch_size={config.max_batch_size}")
                
            else:
                # CPU-only configuration
                config = InferenceConfig(
                    device=InferenceDevice.CPU,
                    device_id=0,
                    max_batch_size=min(2, memory_info["recommended_batch_size"]),
                    max_sequence_length=2048,
                    use_quantization=True,  # Always use quantization on CPU
                    use_mixed_precision=False,  # No mixed precision on CPU
                    gpu_memory_fraction=0.0,
                    cpu_threads=min(cpu_info["cores"], 8)  # Limit CPU threads
                )
                
                logger.info(f"CPU configuration: {config.cpu_threads} threads, batch_size={config.max_batch_size}")
            
            self.optimal_device = config.device
            return config
            
        except Exception as e:
            logger.error(f"Failed to determine optimal config: {e}")
            return self._get_cpu_fallback_config()
    
    def _get_cpu_fallback_config(self) -> InferenceConfig:
        """Get safe CPU fallback configuration"""
        return InferenceConfig(
            device=InferenceDevice.CPU,
            device_id=0,
            max_batch_size=1,
            max_sequence_length=1024,
            use_quantization=True,
            use_mixed_precision=False,
            gpu_memory_fraction=0.0,
            cpu_threads=min(psutil.cpu_count() or 2, 4)
        )
    
    def get_torch_device(self) -> torch.device:
        """Get PyTorch device object for the optimal configuration"""
        if not self.inference_config:
            return torch.device("cpu")
        
        if self.inference_config.device == InferenceDevice.CUDA:
            return torch.device(f"cuda:{self.inference_config.device_id}")
        elif self.inference_config.device == InferenceDevice.MPS:
            return torch.device("mps")
        else:
            return torch.device("cpu")
    
    def get_model_kwargs(self) -> Dict[str, Any]:
        """Get model initialization kwargs based on detected hardware"""
        if not self.inference_config:
            return {"device_map": "cpu"}
        
        kwargs = {}
        
        if self.inference_config.device in [InferenceDevice.CUDA, InferenceDevice.MPS]:
            kwargs["device_map"] = "auto"
            kwargs["torch_dtype"] = torch.float16 if self.inference_config.use_mixed_precision else torch.float32
            
            if self.inference_config.use_quantization:
                # Add quantization config for memory efficiency
                from transformers import BitsAndBytesConfig
                kwargs["quantization_config"] = BitsAndBytesConfig(
                    load_in_4bit=True,
                    bnb_4bit_quant_type="nf4",
                    bnb_4bit_compute_dtype=torch.float16,
                    bnb_4bit_use_double_quant=True
                )
        else:
            # CPU configuration
            kwargs["device_map"] = "cpu"
            kwargs["torch_dtype"] = torch.float32
            
            if self.inference_config.use_quantization:
                kwargs["torch_dtype"] = torch.int8  # Use int8 quantization on CPU
        
        return kwargs
    
    def get_generation_kwargs(self) -> Dict[str, Any]:
        """Get text generation kwargs optimized for detected hardware"""
        if not self.inference_config:
            return {"max_new_tokens": 256}
        
        return {
            "max_new_tokens": 512 if self.inference_config.device != InferenceDevice.CPU else 256,
            "do_sample": True,
            "temperature": 0.7,
            "top_p": 0.9,
            "batch_size": self.inference_config.max_batch_size
        }
    
    async def benchmark_inference(self) -> Dict[str, Any]:
        """Benchmark inference performance on detected hardware"""
        try:
            logger.info("Starting inference benchmark...")
            
            benchmark_results = {
                "device": str(self.inference_config.device),
                "device_id": self.inference_config.device_id,
                "cpu_benchmark": await self._benchmark_cpu(),
                "memory_benchmark": await self._benchmark_memory(),
                "inference_ready": True
            }
            
            if self.inference_config.device in [InferenceDevice.CUDA, InferenceDevice.MPS]:
                benchmark_results["gpu_benchmark"] = await self._benchmark_gpu()
            
            logger.info("Inference benchmark completed successfully")
            return benchmark_results
            
        except Exception as e:
            logger.error(f"Benchmark failed: {e}")
            return {"device": "cpu", "inference_ready": False, "error": str(e)}
    
    async def _benchmark_cpu(self) -> Dict[str, Any]:
        """Benchmark CPU performance"""
        import time
        
        start_time = time.time()
        
        # Simple matrix multiplication benchmark
        size = 1000
        a = torch.randn(size, size)
        b = torch.randn(size, size)
        
        # CPU computation
        with torch.no_grad():
            c = torch.matmul(a, b)
        
        cpu_time = time.time() - start_time
        
        return {
            "cpu_matmul_time": cpu_time,
            "operations_per_second": (size ** 3) / cpu_time,
            "threads_used": self.inference_config.cpu_threads
        }
    
    async def _benchmark_gpu(self) -> Dict[str, Any]:
        """Benchmark GPU performance"""
        import time
        
        device = self.get_torch_device()
        
        start_time = time.time()
        
        # GPU matrix multiplication benchmark
        size = 2000
        a = torch.randn(size, size, device=device)
        b = torch.randn(size, size, device=device)
        
        # GPU computation
        with torch.no_grad():
            c = torch.matmul(a, b)
            if device.type == "cuda":
                torch.cuda.synchronize()
        
        gpu_time = time.time() - start_time
        
        return {
            "gpu_matmul_time": gpu_time,
            "operations_per_second": (size ** 3) / gpu_time,
            "speedup_vs_cpu": 1.0  # Would need CPU benchmark to calculate
        }
    
    async def _benchmark_memory(self) -> Dict[str, Any]:
        """Benchmark memory performance"""
        memory = psutil.virtual_memory()
        
        return {
            "total_memory_gb": memory.total // (1024**3),
            "available_memory_gb": memory.available // (1024**3),
            "memory_utilization": memory.percent,
            "recommended_batch_size": self.inference_config.max_batch_size
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get current hardware detection status"""
        return {
            "detection_completed": self.inference_config is not None,
            "optimal_device": str(self.optimal_device) if self.optimal_device else None,
            "gpu_count": len(self.detected_gpus),
            "gpu_available": len(self.detected_gpus) > 0,
            "cuda_available": torch.cuda.is_available(),
            "mps_available": hasattr(torch.backends, 'mps') and torch.backends.mps.is_available(),
            "inference_config": self.inference_config.__dict__ if self.inference_config else None
        }