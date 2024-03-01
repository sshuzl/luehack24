# Cookie Forum - Writeup

## Forum Page

When opening the website we can see a forum page where the Cookiemonster brags about his Cookies and that with those Cookies he is allowed to see the secrets of the Forum.
His Cookies are `Normal=2005, Super=42`.

He also tells us to look at our Cookies with the Browser and links to a Google search how to do that with the browser Dev Tool. Using the Dev tool we can see that upon entering the site we got the Cookie `Normal=0` (if we play CookieClicker
we up the number).

## Manipulation

Cookiemonster and us both have the Normal Cookie but with different values. If we use the dev tool to change the Value to the one Cookie Monster has (2005) the website changes.
There is a new Forum post from Cookie monster telling us we are on the right way.

## Stealing

Unlike Cookiemonster we don’t have a second Cookie, he has the Cookie Super set to 42. Knowing the Cookie name and value we can use the dev tool to create us a new Cookie Super with value 42. Now with both Cookies set there is a new Forum post saying we stole Cookiemonsters Cookies and we can now see the secret at the top of the page.

