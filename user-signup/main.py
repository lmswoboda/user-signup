#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import getpass
import re

form="""
<form method = "post">
    <h2>Signup</h2>
    <label>Username<input type="text" name="username" value = "%(username)s"</label>
    <div style="color: red">%(error_username)s</div>

    <br>
    <label>Password<input type="password" name="password"></label>
    <div style="color: red">%(error_password)s</div><div style="color: red">%(error_match)s</div>

    <br>
    <label>Verify Password<input type="password" name="verify"></label>
    <div style="color: red">%(error_verify)s</div><div style="color: red">%(error_match)s</div>

    <br>
    <label>Email (optional)<input type="text" name="email" value ="%(email)s"></label>
    <div style="color: red">%(error_email)s</div>

    <br>
    <div style="color: red">%(error)s</div>
    <br>
    <input type = "submit">
</form>
"""
def valid_username(username):
    USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USERNAME_RE.match(username)

def valid_password(password):
    PASSWORD_RE = re.compile(r"^.{3,20}$")
    return PASSWORD_RE.match(password)

def valid_verify(verify):
    VERIFY_RE = re.compile(r"^.{3,20}$")
    return VERIFY_RE.match(verify)

def valid_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    if email == "" or EMAIL_RE.match(email):
        return True

def password_verify_match(user_password, user_verify):
    if user_password == user_verify:
        return True
    else:
        return False


class MainHandler(webapp2.RequestHandler):
    def write_form(self, error="", username="", email="", password="", verify="",
                    error_username="", error_password="", error_verify="",
                    error_email="", error_match=""):
        self.response.write(form % {"error": error,
                                    "username": username,
                                    "email": email,
                                    "error_username": error_username,
                                    "error_password": error_password,
                                    "error_verify": error_verify,
                                    "error_email": error_email,
                                    "error_match": error_match})
    def get(self):
        self.write_form()

    def post(self):
        error=""
        username=""
        email=""
        error_username=""
        error_password=""
        error_verify=""
        error_email=""
        error_match=""


# retrieving user input
        user_username = cgi.escape(self.request.get("username"))
        user_password = cgi.escape(self.request.get("password"))
        user_verify = cgi.escape(self.request.get("verify"))
        user_email = cgi.escape(self.request.get("email"))

# testing user input is valid
        username = valid_username(user_username)
        password = valid_password(user_password)
        verify = valid_verify(user_verify)
        email = valid_email(user_email)
        match = password_verify_match(user_password, user_verify)

#incorrect input
        if not username:
            error_username = "Invalid username."
        if not password:
            error_password = "Invalid password."
        if not verify:
            error_verify = "Invalid password."
        if not email:
            error_email = "Invalid email address."
        if not match:
            error_match = "Your password and verify password did not match."

        self.write_form("Please try again", user_username, user_password, user_verify, user_email,
                        error_username, error_password, error_verify, error_email, error_match)

        if (username and password and verify and email and match):
            self.redirect("/welcome?username="+ user_username)



class WelcomeHandler(webapp2.RequestHandler):

    def get(self):
        username = self.request.get("username")

        self.response.write("Welcome, " + username + "!")



app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', WelcomeHandler)
], debug=True)
