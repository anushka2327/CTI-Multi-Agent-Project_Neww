
import chromadb
from sentence_transformers import SentenceTransformer


# ==========================================
# CONFIGURATION
# ==========================================

CHROMA_PATH = "./chroma_db"
COLLECTION_NAME = "rag_knowledge_base"


# ==========================================
# LOAD EMBEDDING MODEL
# ==========================================

embedding_model = SentenceTransformer(
    "all-MiniLM-L6-v2"
)


# ==========================================
# CONNECT TO CHROMADB
# ==========================================

client = chromadb.PersistentClient(
    path=CHROMA_PATH
)

collection = client.get_collection(
    name=COLLECTION_NAME
)


# ==========================================
# RETRIEVER FUNCTION
# ==========================================

def retrieve(query, n_results=5):

    """
    Search the ChromaDB knowledge base and
    return the most relevant document chunks.
    """

    # --------------------------------------
    # Convert query into embedding
    # --------------------------------------

    query_embedding = embedding_model.encode(
        query
    ).tolist()


    # --------------------------------------
    # Search ChromaDB
    # --------------------------------------

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results,
        include=[
            "documents",
            "metadatas",
            "distances"
        ]
    )


    # --------------------------------------
    # Extract results
    # --------------------------------------

    retrieved_chunks = results["documents"][0]
    metadatas = results["metadatas"][0]
    distances = results["distances"][0]


    # --------------------------------------
    # Store results in structured format
    # --------------------------------------

    retrieved_data = []

    for i in range(len(retrieved_chunks)):

        retrieved_data.append({

            "text": retrieved_chunks[i],

            "source": metadatas[i]["source"],

            "page": metadatas[i]["page"],

            "distance": distances[i]

        })


    return retrieved_data


# ==========================================
# TEST RETRIEVAL
# ==========================================

if __name__ == "__main__":

    question = input("\nAsk a question: ")

    results = retrieve(question)


    print("\n==========================================")
    print("RETRIEVED INFORMATION")
    print("==========================================")


    for i, result in enumerate(results):

        print("\n------------------------------------------")

        print(f"Result {i + 1}")

        print("Source:", result["source"])

        print("Page:", result["page"])

        print("Distance:", result["distance"])

        print("------------------------------------------")

        print(result["text"][:500])


    print("\n==========================================")
    print("RETRIEVAL COMPLETE")
    print("==========================================")
