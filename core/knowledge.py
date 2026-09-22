import os
from langchain_community.document_loaders import TextLoader
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

def load_knowledge_base():
    """
    Crea o carga una base de conocimiento vectorial local para el agente.
    """
    embeddings = OpenAIEmbeddings()
    kb_path = "knowledge_base"
    
    # Si hay documentos de conocimiento técnico, los indexa
    if os.path.exists(kb_path) and os.listdir(kb_path):
        documents = []
        for file in os.listdir(kb_path):
            if file.endswith(".md") or file.endswith(".txt"):
                loader = TextLoader(os.path.join(kb_path, file))
                documents.extend(loader.load())
        
        if documents:
            text_splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
            docs = text_splitter.split_documents(documents)
            vectorstore = FAISS.from_documents(docs, embeddings)
            return vectorstore.as_retriever(search_kwargs={"k": 2})
            
    return None