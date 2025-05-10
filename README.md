# Lab: JWT with Flask and React

## Introduction



## Tools & Resources



## Set Up

As with other labs in this section, there is some starter code in place for a
Flask API backend and a React frontend. To get set up, run:

```bash
pipenv install && pipenv shell
npm install --prefix client
cd server
flask db init
flask db migrate -m "initial migration"
flask db upgrade head
python seed.py
```

You can work on this lab by running the tests with `pytest`. It will also be
helpful to see what's happening during the request/response cycle by running the
app in the browser. You can run the Flask server with:

```bash
python app.py
```

Note that running `python app.py` will generate an error if you haven't created
your models and run your migrations yet.

And you can run React in another terminal from the project root directory with:

```bash
npm start --prefix client
```

## Instructions

### Task 1: Define the Problem

### Task 2: Determine the Design

### Task 3: Develop, Test, and Refine the Code

#### Step x: Verify and Refine your Code

#### Step x: Commit and Push Git History

* Commit and push your code:

```bash
git add .
git commit -m "final solution"
git push
```

* If you created a separate feature branch, remember to open a PR on main and merge.

### Task 4: Document and Maintain

Optional Best Practice documentation steps:
* Add comments to the code to explain purpose and logic, clarifying intent and functionality of your code to other developers.
* Update README text to reflect the functionality of the application following https://makeareadme.com. 
  * Add screenshot of completed work included in Markdown in README.
* Delete any stale branches on GitHub
* Remove unnecessary/commented out code
* If needed, update git ignore to remove sensitive data

## Submit your solution

CodeGrade will use the same test suite as the test suite included.

Once all tests are passing, commit and push your work using `git` to submit to CodeGrade through Canvas.