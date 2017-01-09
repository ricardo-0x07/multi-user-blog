# MIT License

# Copyright (c) 2016 Clive Cadogan

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from google.appengine.ext import db
import random
import string
import hashlib


def make_salt():
    """Make salt: a random 5 charater string to be used to hash passwords.

    Args: None.
    Returns: a random 5 character string for hashing password.
    """
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw, salt=None):
    """Create a password hash.

    Args: None.
    Returns: a hash of the plaintext password and the salt.
    """
    if not salt:
        salt = make_salt()
    hash = hashlib.sha256(name + pw + salt)
    hashed = hash.hexdigest()
    return '%s,%s' % (hashed, salt)


def valid_pw(name, pw, h):
    """Validate plaintext password entered by the user againts the hashed password.

    Args: name: name of the user. pw: users plaintext password. h: users stored
    password hash.
    Returns: Boolean values True/False if password is valid or not.
    """
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)


def users_key(group='default'):
    """Get users key.

    Args: group: name of group.
    Returns: database key for a specific group of users.
    """
    return db.Key.from_path('bloggers', group)


def blog_key(name='default'):
    """Get blog key.

    Args: name: name of group.
    Returns: database key for a specific group of blogs.
    """
    return db.Key.from_path('blogs', name)


class Blogger(db.Model):
    """Blogger entity definition."""

    name = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, uid):
        """Fetch blogger entity by it's id.

        Args: uid: id number of the blogger entity.
        Returns: the retrieved blogger entity or None if not found.
        """
        return cls.get_by_id(uid, parent=None)

    @classmethod
    def by_name(cls, name):
        """Fetch blogger entity by it's name.

        Args: name: user name of the blogger entity.
        Returns: the retrieved blogger entity or None if not found.
        """
        blogger = cls.all().filter('name =', name).get()
        return blogger

    @classmethod
    def register(cls, name, pw, email=None):
        """Create blogger entity without saving.

        Args: name: user name of the blogger entity.
            pw: plain text password of the blogger entity.
            email: optional email address of the blogger entity.
        Returns: the create blogger entity.
        """
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=None,
                   name=name,
                   password=pw_hash,
                   email=email)

    @classmethod
    def get_valid_user(cls, name, pw):
        """Get user and validate login password.

        Args: name: user name of the blogger entity.
            pw: plain text password the user hasattmpted to signin with.
        Returns: the retrieved blogger entity once password has been validated
        or None if not found or the password is not validated.
        """
        blogger = cls.by_name(name)
        if blogger and valid_pw(name, pw, blogger.password):
            return blogger


class Post(db.Model):
    """Post entity definition."""

    title = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    user = db.ReferenceProperty(Blogger, collection_name='posts')
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, uid):
        """Fetch post entity by it's id.

        Args: uid: id number of the post entity.
        Returns: the retrieved post entity or None if not found.
        """
        return cls.get_by_id(uid, parent=None)

    @classmethod
    def by_name(cls, title):
        """Fetch post entity by it's name.

        Args: name: user name of the post entity.
        Returns: the retrieved post entity or None if not found.
        """
        post = cls.all().filter('title =', title).get()
        return post

    @classmethod
    def create(cls, title, body):
        """Create post entity without saving.

        Args: name: user name of the post entity.
            pw: plain text password of the post entity.
            email: optional email address of the post entity.
        Returns: the create post entity.
        """
        return cls(parent=None,
                   title=title,
                   body=body)


class Like(db.Model):
    """Like entity definition."""

    user = db.ReferenceProperty(Blogger, collection_name='likes')
    post = db.ReferenceProperty(Post, collection_name='likes')
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, uid):
        """Fetch like entity by it's id.

        Args: uid: id number of the like entity.
        Returns: the retrieved like entity or None if not found.
        """
        return cls.get_by_id(uid, parent=None)

    @classmethod
    def create(cls, user, post):
        """Create and save new or delete existing  like entity.

        Determine if the logged in user has like a post already
        and if the have the like will deleted i.e. unliked.
        If the user has not like the post previoulsy a new like
        will be created abd saved.

        Args: user: user entity to check for existing like of a specified post.
            post: post entity to be used to possible existing user like.
        Returns: key to newly created like entity.
        """
        like = user.likes.filter('post =', post).get()
        if like:
            like.delete()
        else:
            a = cls(user=user, post=post)
            return a.put()


class Comment(db.Model):
    """Docstring for Comment."""

    content = db.TextProperty(required=True)
    user = db.ReferenceProperty(Blogger, collection_name='comments')
    post = db.ReferenceProperty(Post, collection_name='comments')
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, uid):
        """Docstring for by_id."""
        return cls.get_by_id(uid, parent=None)

    @classmethod
    def create(cls, content, user, post):
        """Docstring for create."""
        a = cls(content=content, user=user, post=post)
        return a.put()
