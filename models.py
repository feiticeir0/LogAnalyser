from langchain_ollama import ChatOllama
import multiprocessing


def get_llm():
    """Build and return the configured Ollama chat model used for log analysis."""
    return ChatOllama(
        model="mistral:7b-instruct-v0.3-q8_0",
        # Leave one CPU core free so request handling stays responsive.
        num_thread=max(1, multiprocessing.cpu_count() - 1),
        # Lower randomness gives more stable and repeatable incident analysis.
        temperature=0.15,
        # ChatOllama expects num_ctx/num_predict (not n_ctx/max_tokens).
        num_ctx=8192,
        num_predict=384,
        top_p=0.9,
    )
