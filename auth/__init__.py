"""
Authentication functions for firebase-admin.
Use functions in an executor for async cases.
"""
import json
from abc import ABCMeta, abstractclassmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Literal, NamedTuple, Optional, Type, TypeVar, Union

import firebase_admin
import requests
from firebase_admin import App, auth, credentials, exceptions
from firebase_admin.auth import UserRecord


T = TypeVar("T")
"""Represents any object that has database access. Most often, these are the running
`app` instances of the used web framework."""

ID = Union[str, int]

API_URL = "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
"""
Firebase API against which we make requests to authenticate users.
"""


class Container(NamedTuple):
    """
    NamedTuple binding the App and api-key in a single structure.
    """
    app: App
    api_key: str


class AuthenticationError(Exception):
    """
    Base exception for any authentication related errors.
    """


class UnauthenticatedError(AuthenticationError):
    """
    Exception raised when a user tries to access a route that they aren't
    authenticated for.
    """


def initialize_app_and_config(fp: Union[str, Path], api_key: str) -> Container:
    """
    Function to initialize the firebase_admin app.
    Pass the object returned by this function to all other functions
    that need the firebase app instance.
    
    Arguments:
        fp: The path to the firebase credentials JSON file.
        api_key: API key for the firebase project.
    Returns:
        Initialized firebase_admin app in a Container.
    """
    cred = credentials.Certificate(fp)
    app = firebase_admin.initialize_app(cred)

    return Container(
        app=app,
        api_key=api_key
    )


@dataclass
class User(metaclass=ABCMeta):
    """
    Abstract base class representing a user for the web app.
    """

    id: ID
    # add whatever more fields are needed, but the ID should be compulsory

    @abstractclassmethod
    @classmethod
    def by_id(cls, db_handle: T, id: ID) -> "User":
        """
        Classmethod to retrieve a User's data by their ID.
        """
        ...
    

def create_user(
    container: Container, *, username: str, email: str, password: str
) -> Optional[UserRecord]:
    """
    Creates a new user on Firebase.
    This function does not create the user in our database.
    """
    try:
        user = auth.create_user(
            app=container.app, display_name=username, email=email, password=password
        )
        return user
    except Exception as e:
        if isinstance(e, ValueError):
            raise ValueError("Invalid values provided") from e
        elif isinstance(e, exceptions.FirebaseError):
            raise RuntimeError(
                f"Firebase raised an error while creating user {username}"
            ) from e


def get_user(container: Container, uid: str) -> UserRecord:
    """
    Gets a user from firebase.
    """
    return auth.get_user(app=container.app, uid=uid)


def authenticate_user(container: Container, email: str, password: str) -> Optional[dict]:
    """
    Authenticate a user with email and password.
    This will be used while logging in.
    Returns:
        None, if the user failed authentication
        Raw response dictionary from the API if the user passed authentication.
        This dictionary will be added to the user's `session` to retrieve user ID later.
    """
    payload = json.dumps(
        {"email": email, "password": password, "returnSecureToken": True}
    )
    response = requests.post(API_URL, params={"key": container.api_key}, data=payload)

    data = response.json()

    if not data.get("idToken"):
        # the API didn't give back a regenerate token, so the authentication was a failure
        return
    else:
        return data


def create_session_cookie(container: Container, data: dict) -> Union[dict, Literal[False]]:
    """
    Creates a session cookie for a user with the given `idToken`.
    Arguments:
        container: Container
        data: dict -> The raw response dictionary sent by the Firebase API on a succesful login.
        This will be returned by the `authenticate_user` function.
    Returns ::
        ON SUCCESS =>
        Dictionary with 2 keys:
            session_cookie: bytes
            expires: datetime.datetime
        NOTE: Don't forget to set the session_cookie on the HttpResponse!
        ON FAILURE =>
        boolean False
    """
    id_token = data.get("idToken")
    expires_in = timedelta(days=5)

    try:
        session_cookie = auth.create_session_cookie(
            id_token=id_token, expires_in=expires_in, app=container.app
        )
        expires = datetime.now(timezone.utc) + expires_in
        return {"session_cookie": session_cookie, "expires": expires}
    except exceptions.FirebaseError:
        return False



def check_logged_in(request: Any) -> Union[dict, Literal[False]]:
    """
    Checks whether a user is signed in (on Firebase, with email and password).
    Arguments:
        request: The request object. This _may_ not work for all frameworks.
            (Should work for django, sanic w/ sanic-session, fastapi)
    Returns:
        The validated user details if True, else `bool` False.
    """
    firebase_session_cookie = request.session.get(
        "firebase-session-cookie"
    )  # the dict returned by create_session_cookie

    if not firebase_session_cookie:
        return False

    try:
        session_cookie_string = firebase_session_cookie.get("session_cookie")
        val = auth.verify_session_cookie(session_cookie_string, check_revoked=True)
        return val
    except auth.InvalidSessionCookieError:
        return False

    
def delete_session_cookie(request: Any) -> None:
    """
    Clears the session cookie. Meant to be used on sign out.

    Arguments:
        request: The request object. This _may_ not work for all frameworks.
            (Should work for django, sanic w/ sanic-session, fastapi)
    """
    firebase_session_cookie = request.session.get("firebase-session-cookie")
    session_cookie_string = firebase_session_cookie.get("session_cookie")
    try:
        decoded_claims = auth.verify_session_cookie(
            session_cookie_string, check_revoked=True
        )
        auth.revoke_refresh_tokens(decoded_claims["sub"])
    except auth.InvalidSessionCookieError:
        raise AuthenticationError("Tried to revoke an invalid session cookie.")


def authenticated(db_handle: T, *, user_class: Type[User]) -> Callable:
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(
            request: Any, *args: Any, **kwargs: Any
        ) -> Any:
            """
            Decorator that checks if a user is signed in.
            The decorator will inject an argument:
                user: User -> The User object for the signed in user.
            """
            from_firebase = check_logged_in(request)

            if from_firebase:
                user = user_class.by_id(db_handle=db_handle, id=from_firebase["uid"])
                return func(request, user=user, *args, **kwargs)
            else:
                raise UnauthenticatedError("Not logged in.")

        return wrapper

    return decorator
