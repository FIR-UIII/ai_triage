import os

from langchain_chroma import Chroma
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import OllamaEmbeddings 


# Define the persistent directory
current_dir = os.path.dirname(os.path.abspath(__file__))
# persistent_directory = os.path.join(current_dir, "chroma_db")
persistent_directory = os.path.join(current_dir, "chroma_db_metadata")

# Define the embedding model
embeddings = OllamaEmbeddings(model="nomic-embed-text:latest", base_url="http://localhost:11434")

# Load the existing vector store with the embedding function
db = Chroma(collection_name="example_collection", embedding_function=embeddings, persist_directory=persistent_directory)

# Define question
search_query = "Какие уязвимости относятся к musl версии 1.2.5-r10?"

docs = db.similarity_search_with_relevance_scores(
    query=search_query,
    score_threshold=0.7,  # порог релевантности
    k=4  # сколько чанков (document) вернуть
)

for doc in docs:
    print(f"Content: {doc[0].page_content}")
    print(f"Metadata: {doc[0].metadata}")
    print("-" * 40)


# ==========================

# # Retrieve relevant documents based on the query
# retriever = db.as_retriever(
#     search_type="similarity",
#     search_kwargs={"k": 3},
# )

# relevant_docs = retriever.invoke(query)

# Display the relevant results with metadata
# print("\n--- Relevant Documents ---")
# for i, doc in enumerate(relevant_docs, 1):
#     print(f"Document {i}:\n{doc.page_content}\n")

# # Combine the query and the relevant document contents
# combined_input = (
#     "Here are some documents that might help answer the question: "
#     + query
#     + "\n\nRelevant Documents:\n"
#     + "\n\n".join([doc.page_content for doc in relevant_docs])
#     + "\n\nPlease provide an answer based only on the provided documents. If the answer is not found in the documents, respond with 'I'm not sure'."
# )

# # Create a ChatOpenAI model
# llm = OllamaLLM(
#     model="phi3:mini", 
#     base_url="http://localhost:11434",
#     temperature=0.3,
#     max_tokens=64,
#     timeout=30,
#     max_retries=0,
#     # other params...
# )

# # Define the messages for the model
# messages = [
#     SystemMessage(content="You are a helpful assistant."),
#     HumanMessage(content=combined_input),
# ]

# # Invoke the model with the combined input
# result = llm.invoke(messages)

# # Display the full result and content only
# print("\n--- Generated Response ---")
# print(result)