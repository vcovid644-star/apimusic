FROM python:3.11

# instala node
RUN apt-get update && apt-get install -y nodejs npm

# cria pasta
WORKDIR /app

# copia tudo
COPY . .

# instala deps
RUN pip install -r requirements.txt

# inicia servidor
CMD ["gunicorn", "server:app", "--bind", "0.0.0.0:10000"]
