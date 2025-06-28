# Open Source LLM Integration for NeuroCipher

## ✅ **Supported Open Source LLM Methods:**

### 1. **Ollama (Recommended - FREE)**
```bash
# Install Ollama
brew install ollama  # macOS
# or visit: https://ollama.ai

# Start Ollama
ollama serve

# Download open source models
ollama pull llama3.2        # Meta's Llama 3.2 
ollama pull codellama       # Code-focused model
ollama pull mistral         # Mistral 7B
ollama pull phi3            # Microsoft Phi-3
ollama pull qwen2.5         # Alibaba Qwen 2.5
```

**Configure in zen-mcp-server:**
```bash
# Edit ~/.zen-mcp-server/.env
CUSTOM_API_URL=http://localhost:11434/v1
CUSTOM_API_KEY=                    # Leave empty for Ollama
CUSTOM_MODEL_NAME=llama3.2         # Default model
```

### 2. **LM Studio (GUI)**
- Download: https://lmstudio.ai
- Local server with web UI
- Supports all popular open source models
- Configure: `CUSTOM_API_URL=http://localhost:1234/v1`

### 3. **vLLM (High Performance)**
```bash
# Install vLLM
pip install vllm

# Start server with open source model
python -m vllm.entrypoints.openai.api_server \
    --model microsoft/DialoGPT-medium \
    --port 8000

# Configure: CUSTOM_API_URL=http://localhost:8000/v1
```

### 4. **Hugging Face Transformers**
```bash
# Install transformers
pip install transformers torch

# Use with text-generation-inference
docker run --gpus all --shm-size 1g -p 8080:80 \
    ghcr.io/huggingface/text-generation-inference:latest \
    --model-id microsoft/DialoGPT-medium
```

## **Benefits for NeuroCipher:**

### 🔐 **Privacy & Security**
- **No data leaves your infrastructure**
- **GDPR/HIPAA compliant** - customer data stays local
- **No API keys needed** for local models
- **Air-gapped deployment** possible

### 💰 **Cost Advantages**
- **FREE unlimited usage** - no per-token charges
- **No monthly subscriptions** to external APIs
- **Predictable costs** - only hardware/electricity
- **Scale without cost increases**

### 🚀 **Performance Benefits**
- **No network latency** - local inference
- **GPU acceleration** available
- **Custom fine-tuning** on cybersecurity data
- **24/7 availability** - no API rate limits

## **Recommended Open Source Models for NeuroCipher:**

### **General Purpose:**
- **Llama 3.2 (8B)** - Best overall performance
- **Mistral 7B** - Fast and efficient
- **Qwen 2.5 (7B)** - Strong reasoning

### **Code & Security:**
- **CodeLlama** - Code analysis and review
- **DeepSeek Coder** - Security-focused coding
- **StarCoder** - Code generation

### **Specialized:**
- **Phi-3 Mini** - Lightweight, fast responses
- **Gemma 7B** - Google's open model
- **Yi 34B** - High-quality responses

## **Integration Examples:**

### **Customer Support with Local LLM:**
```python
# Configure for Ollama
zen_config = {
    "CUSTOM_API_URL": "http://localhost:11434/v1",
    "CUSTOM_MODEL_NAME": "llama3.2",
    "DEFAULT_MODEL": "custom"
}

# Use for customer support
response = await zen.customer_support_chat(
    "What cybersecurity services do you offer?",
    model="llama3.2"  # Uses local open source model
)
```

### **Security Content Generation:**
```python
# Generate security blog post with local model
content = await zen.generate_security_content(
    "blog_post",
    "zero-day vulnerability protection",
    model="codellama"  # Local code-focused model
)
```

## **Hardware Requirements:**

### **Minimum (CPU Only):**
- 8GB RAM for 7B models
- 16GB RAM for 13B models
- Works on any modern CPU

### **Recommended (GPU):**
- NVIDIA GPU with 8GB+ VRAM
- Apple Silicon M1/M2/M3 (unified memory)
- Dramatically faster inference

### **Enterprise (High Performance):**
- Multiple GPUs
- 32GB+ RAM
- Can run larger 70B+ models

## **Setup Instructions:**

### **1. Install Ollama (Easiest)**
```bash
# Install
curl -fsSL https://ollama.ai/install.sh | sh

# Start service
ollama serve

# Download models
ollama pull llama3.2
ollama pull codellama
ollama pull mistral
```

### **2. Configure zen-mcp-server**
```bash
# Edit config
nano ~/.zen-mcp-server/.env

# Add these lines:
CUSTOM_API_URL=http://localhost:11434/v1
CUSTOM_API_KEY=
CUSTOM_MODEL_NAME=llama3.2
DEFAULT_MODEL=custom
```

### **3. Test Integration**
```bash
# Start zen-mcp-server
zen-mcp-server

# Test with local model
/chat "Tell me about NeuroCipher's AI cybersecurity platform"
```

## **Cost Comparison:**

| Method | Cost | Privacy | Performance |
|--------|------|---------|-------------|
| **OpenAI API** | $0.03/1K tokens | ❌ External | ⚡ Fast |
| **Open Source Local** | **FREE** | ✅ **100% Private** | ⚡ Fast (with GPU) |
| **Cloud Open Source** | $0.001/1K tokens | ⚠️ Shared | ⚡ Very Fast |

## **For NeuroCipher SMB Customers:**

✅ **Sell this as a feature:**
- "Your data never leaves your infrastructure"
- "No ongoing AI API costs"
- "Complete privacy and compliance"
- "Custom models trained on your data"

This makes NeuroCipher **more attractive to security-conscious SMBs** who want AI benefits without privacy risks!