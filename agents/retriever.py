import sys
from pathlib import Path

sys.path.append(
    str(Path(__file__).resolve().parent.parent)
)

from rag import retrieve


# ==========================================
# RETRIEVER AGENT
# ==========================================

def retriever_agent(query, n_results=5):

    """
    Retriever Agent

    Takes a user query and retrieves the most
    relevant information from the cybersecurity
    knowledge base using the RAG retrieval system.
    """

    print("\n==========================================")
    print("RETRIEVER AGENT")
    print("==========================================")

    print("Query:", query)

    # --------------------------------------
    # Retrieve relevant information
    # --------------------------------------

    results = retrieve(
        query,
        n_results=n_results
    )

    # --------------------------------------
    # Display retrieved information
    # --------------------------------------

    print("\nRetrieved", len(results), "results.")

    for i, result in enumerate(results):

        print("\n------------------------------------------")
        print(f"Result {i + 1}")
        print("------------------------------------------")

        print("Source:", result["source"])
        print("Page:", result["page"])
        print("Distance:", result["distance"])

        print("\nText:")
        print(result["text"][:500])

    return results


# ==========================================
# TEST RETRIEVER AGENT
# ==========================================

if __name__ == "__main__":

    question = input(
        "\nAsk a cybersecurity question: "
    )

    results = retriever_agent(question)

    print("\n==========================================")
    print("RETRIEVER AGENT COMPLETE")
    print("==========================================")

