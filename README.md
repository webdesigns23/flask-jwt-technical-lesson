# Technical Lesson: JWT with Flask and React

## Introduction



## Tools & Resources

- [GitHub Repo]()
- [Flask JWT Extended Documentation](https://flask-jwt-extended.readthedocs.io/en/stable/basic_usage.html)

## Set Up

There is some starter code in place for a Flask API backend and a React frontend.

To get set up, run:

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

Our current app uses session-based authentication, where the backend stores login state in the session. This approach doesn't scale well for stateless services or frontend frameworks like React that expect token-based authentication.

We need to:
* Remove session reliance
* Issue JWTs upon login
* Protect routes using JWT verification
* Store and transmit tokens from the frontend

### Task 2: Determine the Design

We’ll implement the following architecture:

Backend:
* POST /login: Authenticates user and returns a JWT
* GET /check_session: Returns current user (if they exist)
* POST /logout: Frontend simply deletes the token
* Protected Routes: Use JWT rather than sessions to protect routes

Frontend
* Stores JWT in memory or localStorage
* Sends token in the Authorization header of protected requests:

```makefile
Authorization: Bearer <token>
```

### Task 3: Develop, Test, and Refine the Code

#### Step 1: Install and Set Up JWT

First we need to install flask-jwt-extended.

```bash
pipenv install flask-jwt-extended
```

Next, in `config.py`, we'll set up our instance of `JWTManager`:

```python
# config.py

#other imports
from flask_jwt_extended import JWTManager

# app set up
app.config["JWT_SECRET_KEY"] = "i-should-be-secret-and-stored-in-env-variables"

jwt = JWTManager(app)
```

You can change the secret key to be anything you like, but do note that you will push it to GitHub, so it won't really be 'secret' like it should be for an application in production.

> Note: In production, we would want to protect the secret key like the name
> suggests. For educational purposes we're exposing the key here, but
> normally you'd set this using environment variables just like if we were
> implementing auth with sessions. If you deploy any of your applications, you'll want to
> set an environment variable for the secret key and ensure it's not exposed in your GitHub
> commit history anywhere.

We can also remove the secret key we were using for sessions. Feel free to delete this line:

```python
app.secret_key = b'Y\xf1Xz\x00\xad|eQ\x80t \xca\x1a\x10K'
```

Import our `JWTManager` instance in `app.py`:

```python
# app.py

from config import app, db, api, jwt
```

Import `verify_jwt_in_request`, `get_jwt_identity`, and `create_access_token` from flask_jwt_extended:

```python
# app.py

from flask_jwt_extended import create_access_token, get_jwt_identity, verify_jwt_in_request
```

#### Step 2: Add JWT to Login Route

Currently, our login route uses sessions:

```python
class Login(Resource):
    def post(self):

        username = request.get_json()['username']
        password = request.get_json()['password']

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return UserSchema().dump(user), 200

        return {'errors': ['401 Unauthorized']}, 401
```

Let's refactor to use JWT:

```python
class Login(Resource):
    def post(self):

        username = request.json['username']
        password = request.json['password']

        user = User.query.filter(User.username == username).first()

        if user and user.authenticate(password):
            token = create_access_token(identity=user.id)
            return make_response(jsonify(token=access_token, user=UserSchema().dump(user)), 200)

        return {'errors': ['401 Unauthorized']}, 401
```

#### Step 3: Add JWT to Check Session Route

Take a peek at our current check session route:

```python
class CheckSession(Resource):
    def get(self):

        user = User.query.filter(User.id == session['user_id']).first()
        
        return UserSchema().dump(user), 200
```

Let's refactor to use JWT, using `get_jwt_identity`:

```python
class CheckSession(Resource):
    def get(self):
        user_id = get_jwt_identity()
            
        user = User.query.filter(User.id == user_id).first()
        
        return UserSchema().dump(user), 200
```

#### Step 4: Refactor Sign Up

Let's refactor sign up next:

```python
session['user_id'] = user.id
```

Instead of session['user_id'], just like login we'll use create_access_token and return that token.

```python
access_token = create_access_token(identity=user.id)

return make_response(jsonify(token=access_token, user=UserSchema().dump(user)), 200)
```

#### Step 5: Refactor Logout

In Logout, we don't need to do much as the client will be responsible for deleting the JWT token.

As such, let's remove the Logout resource and remove it from the api

```python
# class Logout(Resource):
#     def delete(self):

#         session['user_id'] = None
#         return {}, 204
```

```python
# api.add_resource(Logout, '/logout', endpoint='logout')
```

#### Step 6: Protect Routes with JWT

For our protected routes, we currently have:

```python
@app.before_request
def check_if_logged_in():
    open_access_list = [
        'signup',
        'login'
    ]

    if (request.endpoint) not in open_access_list and (not session.get('user_id')):
        return {'error': '401 Unauthorized'}, 401
```

Flask JWT has a handy method that we can use to replace `session.get`. Let's refactor to
use `verify_jwt_in_request`:

```python
@app.before_request
def check_if_logged_in():
    open_access_list = [
        'signup',
        'login'
    ]

    if (request.endpoint) not in open_access_list and (not verify_jwt_in_request()):
        return {'error': '401 Unauthorized'}, 401
```

> Note that to use the method we're using in CheckSession (and we'll use in other protected
> routes) `get_jwt_identity` requires us to call `verify_jwt_in_request` first or use the 
> `@jwt_required` decorator.

#### Step 7: Refactor Recipe Create Route

Next, we're assigning a recipe to a user in the create route using sessions currently.

Let's fix that:

```python
recipe = Recipe(
    title=request_json.get('title'),
    instructions=request_json.get('instructions'),
    minutes_to_complete=request_json.get('minutes_to_complete'),
    # user_id=session['user_id']
    user_id=get_jwt_identity()
)
```

#### Step 8: Refactor Frontend

Finally, we need to refactor our frontend to use tokens instead of sessions. While session
cookies are sent with and in requests under the hood, we'll need to configure our requests
a bit more to use web tokens.

When logging in and signing up, instead of just sending a user object, we are now sending an
object with 2 keys: user and token. We need to set that token to localStorage in the frontend
which is a means of storing persisting data on a client's browser.

In `LoginForm.js`, instead of just passing the whole object (which was just our user but now has
both token and user), let's destructure and set onLogin 2 arguments:

```javascript
function handleSubmit(e) {
    e.preventDefault();
    setIsLoading(true);
    fetch("/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ username, password }),
    }).then((r) => {
      setIsLoading(false);
      if (r.ok) {
        r.json().then(({token, user}) => onLogin({token, user}));
      } else {
        r.json().then((err) => setErrors(err.errors));
      }
    });
  }
```

We also use this logic in `SignUpForm`:

```javascript
// r.json().then((user) => onLogin(user));

r.json().then(({token, user}) => onLogin(token, user));
```

Next, let's refactor onLogin to take in both arguments.

Current code:

```javascript
if (!user) return <Login onLogin={setUser} />;
```

Refactor to create an onLogin function that uses setUser and sets our token in localStorage:

```javascript
const onLogin = (token, user) => {
    localStorage.setItem("token", token);
    setUser(user)
}

// ... 

if (!user) return <Login onLogin={onLogin} />;
```

Next, in each of our fetch requests when a user should be logged in, we need to send our token along.

In the useEffect for `App.js`, add an Authorization header with our token from localStorage:

```javascript
useEffect(() => {
  // auto-login
  fetch("/check_session", {
      headers: {
        Authorization: `Bearer ${localStorage.getItem("token")}`
      }
    }).then((r) => {
    if (r.ok) {
      r.json().then((user) => setUser(user));
    }
  });
}, []);
```

In the useEffect for `RecipeList.js`, add an Authorization header with our token from localStorage:

```javascript
useEffect(() => {
  fetch("/recipes", {
    headers: {
      Authorization: `Bearer ${localStorage.getItem("token")}`
    }
  })
    .then((r) => r.json())
    .then(setRecipes);
}, []);
```

In the `handleSubmit` for `NewRecipe`:

```javascript
function handleSubmit(e) {
    e.preventDefault();
    setIsLoading(true);
    fetch("/recipes", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${localStorage.getItem("token")}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        title,
        instructions,
        minutes_to_complete: minutesToComplete,
      }),
    }).then((r) => {
      setIsLoading(false);
      if (r.ok) {
        history.push("/");
      } else {
        r.json().then((err) => setErrors(err.errors));
      }
    });
  }
```

Finally, in `NavBar` we need to clear our token on logout rather than making a fetch request:

```javascript
function handleLogoutClick() {
  // fetch("/logout", { method: "DELETE" }).then((r) => {
  //       if (r.ok) {
  //         setUser(null);
  //       }
  //     });

  localStorage.removeItem("token");
  setUser(null);
}
```

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

## Considerations