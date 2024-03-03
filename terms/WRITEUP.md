# terms - Writeup

We are given a website that contains a wall of text and a button.
If we try to click the button, the button starts moving away from the cursor.
It seems that we have to click the button to get the flag.

The obvious first step would be to open the developer tools to inspect the website.
However, when opening the console, the website detects this and changes its contents to "NO CONSOLE ALLOWED".
But what we can still do, is looking at the page's source code.
There we can see, that some JavaScript is used to move the button around.
We now have several options:

1. Disable JavaScript to make the button stay in place.
2. Understand what request the button would send to the server and send this request manually.
3. Find a way to click the button despite it moving around.

The first option is easily achieved by installing a browser plugin like uMatrix to disable JavaScript for the website.
Then, the button is clickable and we can get the flag.

The second option is a bit more complicated.
The code that implements the button's functionality is the following:

```html
<form action="/terms/" id="accept" method="POST">
    <input type="hidden" name="accept" value="true">
    <input type="submit" value="I Accept">
</form>
```

This code creates a form with a hidden input field and a submit button.
When the button is clicked, the form is submitted to the server.
That means that the server receives a `POST` request to `/terms/` with the body `accept=true`.
We can send this request manually using a tool like `curl` and get the flag:

```bash
curl -X POST https://challenges.sshuzl.de/terms/ -d "accept=true" | grep -oh "SSH{.*}"
```

The third option is the fastest way to solve the challenge.
Instead of trying to click the button, we can simply press `TAB` once.
This selects the button.
Then, we can press `ENTER` to click the button and get the flag.
