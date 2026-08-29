from pathlib import Path
from pypdf import PdfReader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from sentence_transformers import SentenceTransformer
import chromadb
import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# ==========================================
# STEP 1: LOAD PDF DOCUMENTS
# ==========================================

data_folder = Path("Data")

documents = []

for pdf_path in data_folder.glob("*.pdf"):

    reader = PdfReader(pdf_path)

    for page_number, page in enumerate(reader.pages):

        text = page.extract_text()

        if text:
            documents.append({
                "text": text,
                "source": pdf_path.name,
                "page": page_number + 1
            })

print("\n==========================================")
print("1. DOCUMENT LOADING")
print("==========================================")

print("Total pages loaded:", len(documents))


# ==========================================
# STEP 2: CHUNK DOCUMENTS
# ==========================================

splitter = RecursiveCharacterTextSplitter(
    chunk_size=1000,
    chunk_overlap=200
)

chunks = []

for document in documents:

    split_texts = splitter.split_text(document["text"])

    for chunk_text in split_texts:

        chunks.append({
            "text": chunk_text,
            "source": document["source"],
            "page": document["page"]
        })

print("\n==========================================")
print("2. DOCUMENT CHUNKING")
print("==========================================")

print("Total chunks created:", len(chunks))


# ==========================================
# STEP 3: CREATE EMBEDDINGS
# ==========================================

print("\n==========================================")
print("3. EMBEDDING GENERATION")
print("==========================================")

embedding_model = SentenceTransformer(
    "all-MiniLM-L6-v2"
)

texts = [chunk["text"] for chunk in chunks]

embeddings = embedding_model.encode(
    texts,
    show_progress_bar=True
)

print("Embeddings created:", len(embeddings))


# ==========================================
# STEP 4: CONNECT TO CHROMADB
# ==========================================

print("\n==========================================")
print("4. CHROMADB")
print("==========================================")

client = chromadb.PersistentClient(
    path="./chroma_db"
)

# ==========================================
# DELETE OLD DATABASE
# ==========================================

try:
    client.delete_collection(
        name="rag_knowledge_base"
    )
    print("Old knowledge base deleted.")
except Exception:
    print("No old knowledge base found.")


# ==========================================
# CREATE FRESH COLLECTION
# ==========================================

collection = client.create_collection(
    name="rag_knowledge_base"
)


# ==========================================
# STORE NEW CHUNKS
# ==========================================

collection.add(
    ids=[f"chunk_{i}" for i in range(len(chunks))],

    documents=texts,

    embeddings=embeddings.tolist(),

    metadatas=[
        {
            "source": chunk["source"],
            "page": chunk["page"]
        }
        for chunk in chunks
    ]
)

print("New chunks stored in ChromaDB:",
      collection.count())

# ==========================================
# STEP 5: ASK QUESTION
# ==========================================

question = input("\nAsk a question: ")


# ==========================================
# STEP 6: EMBED USER QUESTION
# ==========================================

print("\n==========================================")
print("5. QUERY EMBEDDING")
print("==========================================")

question_embedding = embedding_model.encode(
    question
).tolist()

print("Question converted into embedding.")


# ==========================================
# STEP 7: RETRIEVE RELEVANT CHUNKS
# ==========================================

print("\n==========================================")
print("6. RETRIEVAL")
print("==========================================")

results = collection.query(
    query_embeddings=[question_embedding],
    n_results=5,
    include=["documents", "metadatas", "distances"]
)

retrieved_chunks = results["documents"][0]
metadatas = results["metadatas"][0]
distances = results["distances"][0]

print("\nTop retrieved chunks:\n")

for i, chunk in enumerate(retrieved_chunks):

    print("------------------------------------------")
    print(f"Result {i + 1}")
    print("Source:", metadatas[i]["source"])
    print("Page:", metadatas[i]["page"])
    print("Distance:", distances[i])
    print("------------------------------------------")

    print(chunk[:500])

    print()


# ==========================================
# STEP 8: BUILD CONTEXT
# ==========================================

context = "\n\n".join(retrieved_chunks)


# ==========================================
# STEP 9: SEND CONTEXT TO LLM
# ==========================================

print("\n==========================================")
print("7. GENERATING ANSWER")
print("==========================================")

llm_client = Groq(
    api_key=os.getenv("GROQ_API_KEY")
)

prompt = f"""
You are a cybersecurity knowledge assistant.

Answer the user's question using ONLY the
information contained in the retrieved context.

If the answer cannot be found in the context,
say:

"I could not find the answer in the provided
documents."

Retrieved Context:

{context}

User Question:

{question}

Answer:
"""

response = llm_client.chat.completions.create(
    model="openai/gpt-oss-20b",
    messages=[
        {
            "role": "user",
            "content": prompt
        }
    ],
    temperature=0
)

answer = response.choices[0].message.content


# ==========================================
# STEP 10: DISPLAY FINAL ANSWER
# ==========================================

print("\n==========================================")
print("8. FINAL RAG ANSWER")
print("==========================================")

print(answer)

print("\n==========================================")
print("RAG PIPELINE COMPLETE")
print("==========================================")