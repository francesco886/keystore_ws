FROM python:3.9
ADD . /code
WORKDIR /code
RUN pip install -r requirements.txt

COPY . .

CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]