# Technical Lesson: JWT with Flask and React

## Introduction

In previous lessons, we authenticated users using Flask sessions, which
store identity on the server and maintaining state between requests.
While this works in many scenarios, it creates tight coupling between 
the client and backend and doesn't scale well for stateless APIs, 
especially when building with React or other frontend frameworks.

In this lesson, we’ll refactor our existing Flask and React app to use 
JWT (JSON Web Tokens) instead of sessions. JWT is an industry-standard 
method for transmitting verified identity claims between parties. It 
allows our API to stay stateless while securely identifying users.

You’ll implement token generation during login and signup, replace all 
session logic with JWT verification, and update your frontend to send 
tokens with each protected request. This shift mirrors how most 
real-world single-page apps, mobile clients, and distributed services 
handle authentication today.

## Tools & Resources

- [GitHub Repo](https://github.com/learn-co-curriculum/flask-jwt-technical-lesson)
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

Our current app uses session-based authentication, where the backend stores
login state in the session. This approach doesn't scale well for stateless
services or frontend frameworks like React that expect token-based authentication.

We need to:
* Remove session reliance
* Issue JWTs upon login
* Protect routes using JWT verification
* Store and transmit tokens from the frontend

### Task 2: Determine the Design

To build a secure, stateless authentication system with JWT, we’ll update
both the backend and frontend to follow this architecture:

---

#### Backend (Flask)

Login: Accepts credentials and issues a signed JWT if valid.

Signup: Creates a user and issues a JWT on success.

Check Session: Uses the token to retrieve the current user identity.

Protected Routes: Require valid JWT via verify_jwt_in_request() or @jwt_required.

---

#### Frontend (React)
Stores the JWT token in localStorage after login/signup.

Includes the token in an Authorization header for protected requests:

```
Authorization: Bearer <token>
```

Removes the token from storage on logout and clears user state.

--- 

This model separates concerns cleanly: the backend verifies tokens without
holding state, and the frontend manages the token lifecycle.


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

Finally, "check session" doesn't really make sense for naming since we are no longer using sessions.

Let's rename the route to "/me":

```python
class WhoAmI(Resource):
    def get(self):
        user_id = get_jwt_identity()
            
        user = User.query.filter(User.id == user_id).first()
        
        return UserSchema().dump(user), 200
```

```python
# api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(WhoAmI, '/me', endpoint='me')
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

> Note that to use the method we're using in WhoAmI (and we'll use in other protected
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
  // change from /check_session to me and add header
  fetch("/me", {
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

#### Step 9: Verify and Refine your Code

Run both the Flask app and React application. Try the following:
- Sign Up 
  - Verify valid signup is successful and logs you in.
  - Verify you can't signup with an existing user name.
- Log In
  - Verify you can log in with an existing user.
  - Verify that if the password is incorrect, you aren't logged in.
- Log  out
  - The logout button should navigate you back to the login page.
- Check Session / Me
  - When logged in, on refresh you should stay logged in.
  - When logged out, on refresh you should stay logged out.

Also verify the frontend doesn't crash as you test the functionality. 

#### Step 10: Commit and Push Git History

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

### JWTs Are Stateless

The server does not store login state.

Logging out means deleting the token on the client—there’s no session to destroy.

### Token Security

In production, store tokens in HTTP-only cookies or use short expiration windows.

Avoid long-lived tokens in localStorage in high-risk apps (susceptible to XSS).

### Protecting Routes

Use verify_jwt_in_request() in @app.before_request to guard global access.

Alternatively, use @jwt_required() decorators on individual resources.

### Token Must Be Verified on Each Request

JWTs are self-contained—they must be sent with every request, or access will fail.

Forgetting to send the Authorization header will result in 401 Unauthorized.