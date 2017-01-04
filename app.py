import os
import hmac
import jinja2
import webapp2
import re
import random
import string
import hashlib

from google.appengine.ext import db
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)
secret = 'imsosecret'


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
    hash = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (hash, salt)


def valid_pw(name, pw, h):
    """Validate plaintext password entered by the user againts the hashed password.

    Args: name: name of the user. pw: users plaintext password. h: users stored
    password hash.
    Returns: Boolean values True/False if password is valid or not.
    """
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)


def hash_str(s):
    """Hashe a string with secret.

    Args: s: string to be hashed.
    Return: Hash of string with secret.
    """
    return hmac.new(secret, s).hexdigest()


def make_secure_val(s):
    """Make a secure string of a string and its hash.

    Args: String to be used to create secure value.
    Return: a string of the the original string separated by a comma and the
    secured hash of the string.
    """
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    """Validate a secured string.

    Args: h: secured value to be validated.
    Returns: the string extracted from the secured string.
    """
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val


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


class Handler(webapp2.RequestHandler):
    """Handler defines sevral functions to be inherited by sub classes."""

    def write(self, *a, **kw):
        """Write html strings."""
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """Get template and render with params.

        Args: template: html template. params: list of parameters to
        be inserted into html.
        Returns: jinja template with params inserted.
        """
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        """Call write to print html string to the browser.

        Args: template: html string to be rendered. kw: list of params
        to be insereted.
        """
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, value):
        """Set a secure cooke value.

        Args: name: name of cookie. value: value: to be secured and set.
        """
        cookie_val = make_secure_val(value)
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        """Read secured cookie value.

        Args: name: name of cookie to be read.
        Returns: string value extracted from the secured cookie.
        """
        cookie_val = self.request.cookies.get(name)
        if cookie_val and check_secure_val(cookie_val):
            return check_secure_val(cookie_val)

    def login(self, user):
        """Log In user by setting secured user cookie.

        Args: user entity to provide id to be secured and set user cookie.
        """
        self.set_secure_cookie('user', str(user.key().id()))

    def logout(self):
        """Clear secured user cookie to logout user."""
        self.response.headers.add_header('Set-Cookie',
                                         '%s=%s; Path=/' % ('user', ''))

    def initialize(self, *a, **kw):
        """Initialize application every time the application reloads."""
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user')
        self.user = None
        self.auth = False
        self.params = dict(user=self.user,
                           auth=self.auth)
        if uid:
            uid = int(uid)
            self.user = uid and Blogger.by_id(uid)
            self.auth = True
            self.params = dict(user=self.user,
                               auth=self.auth)

    def isloggedin(self):
        """Check if a suser is loggin.

        Returns: Boolean True/False if a user is loogin or not.
        """
        uid = self.read_secure_cookie('user')
        if not uid:
            self.redirect('/login')
            return False
        else:
            return True

    def allowed_post(self, post_id):
        """Check to see if the logged in user created a post.

        Args: post_id: id number of the post.
        Returns: Boolean True/False if user created the post of not.
        """
        post = Post.by_id(post_id)
        return post.user.key().id() == self.user.key().id()

    def allowed_comment(self, comment_id):
        """Check to see if the logged in user created a post.

        Args: comment_id: id number of the post.
        Returns: Boolean True/False if user created the post of not.
        """
        comment = Comment.by_id(comment_id)
        return comment.user.key().id() == self.user.key().id()


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
            # db.delete_async(like.key())
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


class MainPage(Handler):
    """Main Blog Page, renders all blogs from newest to oldest."""

    def render_front(self):
        """Render fetch all posts and render them."""
        posts = Post.all().order('-created')
        self.params['blogs'] = posts
        # blogs = greetings =
        self.render("blog-main.html", **self.params)

    def get(self):
        """Call render front."""
        self.render_front()


class LikeHandler(Handler):
    """Determine if user is allowed_post to like post or not."""

    def get(self, post_id):
        """Determine if the user is allowed_post to like the post.

        Checks if the poist belongs to the user if it does
        the user redirected to the blogs page with an error message.
        If the post does not belog to the user the user is allowed_post
        to like or unlike the post.

        Args: post_id: id number of the post the user is attempting
        to like or unlike.
        """
        if not self.isloggedin():
            return
        id = int(post_id)
        post = Post.by_id(id)
        error = ""
        user_post = self.user.posts.filter('__key__', post.key()).get()
        if user_post:
            error = 'Unauthorized: Only like attempt to like others posts'
            return self.redirect('/blog/' + post_id + '?error=' + error)
        if post:
            Like.create(self.user, post)
            self.redirect('/blog/' + post_id)


class NewPostHandler(Handler):
    """Create new blog posts."""

    def render_front(self, title="", body="", error=""):
        """Render html for entry of a new post with optional parameters.

        Args: tilte: name of the new post.
              body: contents of the new post.
              error: error message.
        """
        self.params['title'] = title
        self.params['body'] = body
        self.params['error'] = error
        self.render("newpost.html", **self.params)

    def get(self):
        """Docstring for get."""
        if not self.isloggedin():
            return
        self.render_front()

    def post(self):
        """Create and save new post.

        Re-renders new post with errors if title or body are missing.
        """
        title = self.request.get('subject')
        body = self.request.get('content')
        error = ""

        if title and body:
            a = Post(title=title, body=body, user=self.user)
            key = a.put()
            id = str(key.id())
            self.redirect('/blog/' + id)
        else:
            error = "We need both a title and some artwork!"
            self.render_front(title, body, error)


class BlogHandler(Handler):
    """Renders individual posts."""

    def create_comment(self, blog_id):
        """Create new comment.

        Args: blog_id: in number of the blog post the comment is for.
        """
        id = int(blog_id)
        post = Post.by_id(id)
        content = self.request.get('content')
        error = ""

        if content:
            Comment.create(content, self.user, post)
            self.redirect('/blog/' + blog_id)
        else:
            error = "Kindly enter the content for your comment"
            self.redirect('/blog/' + blog_id + '?error=' + error)

    def get(self, blog_id):
        """Render a blog post.

        Args: blog_id: indumner of the blog post to be rendered.
        """
        self.params['error'] = self.request.get('error')
        id = int(blog_id)
        post = Post.by_id(id)
        self.params['blog'] = post
        if not post:
            self.error(404)
            return
        else:
            self.render('blog.html', **self.params)

    def post(self, blog_id):
        """Create new comment.

        Args: blog_id: in number of the blog post the comment is for.
        """
        self.create_comment(blog_id)


class EditPostHandler(Handler):
    """Edit amd update posts."""

    def get(self, blog_id):
        """Allow only loggedin users to edit posts they have created.

        Args: blog_id: id number of the post to be edited.
        """
        if not self.isloggedin():
            return
        id = int(blog_id)
        post = Post.by_id(id)
        # self.params['title'] = post.title
        # self.params['body'] = post.body
        error = ''
        self.params['post'] = post
        if self.allowed_post(id):
            self.set_secure_cookie('editedpost', str(id))
            self.render('editpost.html', **self.params)
        else:
            self.error(404)
            error = 'Unauthorized: Only attempt to edit your own posts'
            self.redirect('/blog/' + blog_id + '?error=' + error)

    def post(self, blog_id):
        """Update edited posts.

        Args: blog_id: id number of the blog post that was edited.
        """
        cookie_val = self.read_secure_cookie('editedpost')
        post_id = int(cookie_val)
        post = Post.by_id(post_id)
        # if post:
        post.title = self.request.get('subject')
        post.body = self.request.get('content')
        self.params['error'] = ""

        if post.title and post.body:
            key = post.put()
            id = str(key.id())
            self.redirect('/blog/' + id)
        else:
            self.params['error'] = "We need both a title and some artwork!"
            self.render('editpost.html', **self.params)


class DeletePostHandler(Handler):
    """Docstring for DeletePostHandler."""

    @db.transactional
    def delete(self, key):
        """Delete post and redirect to blog listing.

        Args: key: post entity key  required to dlete post.
        """
        db.delete_async(key)
        self.redirect('/blog')

    def get(self, blog_id):
        """Delete post and redirect to blog listing.

        Allow only logged in users to only delete their own posts.

        Args: blog_id: id number of post entity to be deleted.
        """
        if not self.isloggedin():
            return
        id = int(blog_id)
        post = Post.by_id(id)
        key = post.key()
        error = ''
        self.params['blog'] = post
        if not self.allowed_post(id):
            error = 'Unauthorized: Only attempt to delete your own posts'
            self.redirect('/blog/' + blog_id + '?error=' + error)
        else:
            self.delete(key)


class EditCommentHandler(Handler):
    """Edit and update comments."""

    def get(self, blog_id, comment_id):
        """Allow only loggedin users to edit posts they have created.

        Args: blog_id: id number of post entity to which the comment belongs.
              comment_id: id number of the blog comment to be edited.
        """
        if not self.isloggedin():
            return
        id = int(blog_id)
        post = Post.by_id(id)
        error = ''
        self.params['blog'] = post
        self.params['edit_comment_id'] = int(comment_id)
        if self.allowed_comment(int(comment_id)):
            self.render('blog.html', **self.params)
        else:
            self.error(404)
            error = 'Unauthorized: Only attempt to edit your own posts'
            self.redirect('/blog/' + blog_id + '?error=' + error)

    def post(self, blog_id, comment_id):
        """Update edited posts.

        Args: blog_id: id number of post entity to which the comment belongs.
              comment_id: id number of the blog comment that was edited.
        """
        id = int(comment_id)
        comment = Comment.by_id(id)
        comment.content = self.request.get('edited-content')
        self.params['error'] = ""

        if comment.content:
            key = comment.put()
            id = str(key.id())
            self.redirect('/blog/' + blog_id)
        else:
            self.params['error'] = "We need both a title and some artwork!"
            self.render('blog.html', **self.params)


class DeleteCommentHandler(Handler):
    """Delete user comments."""

    @db.transactional
    def delete(self, key, blog_id):
        """Delete post and redirect to blog listing.

        Args: key: post entity key  required to delete comment.
              blog_id: id number of post entity to which the comment belongs.
        """
        db.delete_async(key)
        self.redirect('/blog/' + blog_id)

    def get(self, blog_id, comment_id):
        """Delete post and redirect to blog listing.

        Allow only logged in users to only delete their own posts.

        Args: blog_id: id number of post entity to which the comment belongs.
              comment_id: id number of comment entity to be deleted.
        """
        if not self.isloggedin():
            return
        id = int(comment_id)
        comment = Comment.by_id(id)
        key = comment.key()
        error = ''
        if not self.allowed_comment(id):
            error = 'Unauthorized: Only attempt to delete your own posts'
            self.redirect('/blog/' + blog_id + '?error=' + error)
        else:
            self.delete(key, blog_id)


class SignUpHandler(Handler):
    """Sign up new bloggers."""

    def valid_username(self, username):
        """Validate user name.

        Args: username: string of the name the user signs up with.
        Returns: Boolean value True/False if the the username
        value is valid or not.
        """
        username_pattern = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return username_pattern.match(username)

    def valid_password(self, password):
        """Validate user password.

        Args: password: string of the password the user signs up with.
        Returns: Boolean value True/False if the the password
        value is valid or not.
        """
        password_pattern = re.compile(r"^.{3,20}$")
        return password_pattern.match(password)

    def valid_email(self, email):
        """Validate user email.

        Args: email: string of the email the user signs up with.
        Returns: Boolean value True/False if the the email
        value is valid or not.
        """
        email_pattern = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        return email_pattern.match(email)

    def check_name_duplicate(self, name):
        """Check for existing user with the same name.

        Args: name: string of the name the user signs up with.
        Returns: Boolean value True/False if the the name
        value is a duplicate or not.
        """
        user = Blogger.by_name(name)
        if user:
            return True
        return False

    def get(self):
        """Render the signup form."""
        self.render('signup.html', **self.params)

    def post(self):
        """Create new blogger.

        Validates form entries, registers and saves new blogger.
        """
        have_error = False
        self.params['username_error'] = ''
        self.params['password_error'] = ''
        self.params['email_error'] = ''
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        if self.check_name_duplicate(username):
            self.params['username_error'] = 'User name already exists.'
            have_error = True

        if not(self.valid_username(username)):
            self.params['username_error'] = 'Kindly enter a valid user name.'
            have_error = True

        if not(self.valid_password(password)):
            self.params['password_error'] = 'Kindly enter a valid password.'
            have_error = True
        elif password != verify:
            self.params[
                'password_error'] = 'The passwords you entered do not match.'
            have_error = True

        if not(self.valid_email(email)):
            self.params['email_error'] = 'Kindly enter a valid email.'

        if have_error:
            self.render('signup.html', **self.params)
        else:
            password = make_pw_hash(username, password)
            a = Blogger.register(username, password, email)
            a.put()
            self.login(a)
            self.redirect('/welcome')


class WelcomeHandler(Handler):
    """Render WelcomePage."""

    def get(self):
        """Render WelcomePage once new blogger signs up.

        Redirects to signup page if user cookie is invalid.
        """
        if not self.isloggedin():
            return
        cookie_val = self.read_secure_cookie('user')
        user_id = int(cookie_val)
        user = user_id and Blogger.by_id(user_id)
        if not user:
            # self.error(404)
            self.redirect('/signup')
        else:
            self.render('welcome.html', **self.params)


class LogInHandler(SignUpHandler):
    """Render LogInPage and process login of users."""

    def get(self):
        """Render the login form."""
        self.render('login.html', **self.params)

    def post(self):
        """Process login of user.

        Validates user credentials and re-renders
        for if credentials are invalid and redirects
        to welcome page when user signs insuccessfully.
        """
        self.params['username_error'] = ''
        self.params['password_error'] = ''
        username = self.request.get('username')
        password = self.request.get('password')

        user = Blogger.get_valid_user(username, password)
        if user:
            self.login(user)
            self.redirect('/welcome')
        else:
            self.params['username_error'] = 'Kindly enter a valid credentials'
            self.params['password_error'] = 'Kindly enter a valid credentials'
            self.render('login.html', **self.params)


class LogOutHandler(Handler):
    """Log out signed in user."""

    def get(self):
        """Log out signed in user."""
        self.logout()
        self.redirect('/login')


app = webapp2.WSGIApplication([
    ('/blog', MainPage),
    ('/blog/newpost', NewPostHandler),
    ('/blog/(\d+)', BlogHandler),
    ('/signup', SignUpHandler),
    ('/login', LogInHandler),
    ('/logout', LogOutHandler),
    ('/welcome', WelcomeHandler),
    ('/like/blog/(\d+)', LikeHandler),
    ('/edit/blog/(\d+)', EditPostHandler),
    ('/delete/blog/(\d+)', DeletePostHandler),
    ('/edit/comment/(\d+)/(\d+)', EditCommentHandler),
    ('/delete/comment/(\d+)/(\d+)', DeleteCommentHandler),
], debug=True)
