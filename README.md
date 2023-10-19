## Project Description

## Environment Configure 
- Installing virtual Env
    - pip install pipenv 

- Installing Packages
    - Using Requirement file
        - pipenv install -r requirement.txt
    - Using the Pipfile
        - Change the python version on your local machine 
        - pipenv install 

- Starting Virtual Env
    - pipenv shell 

- Running FastAPI Service Locally 
    - uvicorn app.main:app --reload