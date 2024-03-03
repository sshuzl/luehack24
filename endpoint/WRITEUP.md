# endpoint - Writeup

We are presented a website that does not allow any interaction.
But when inspecting the source code, we can see JavaScript code that looks interesting.

```javascript
<script id="endpoint">
    function endpoint() {
        var xhttp = new XMLHttpRequest();
        xhttp.onreadystatechange = function() {
            if (this.readyState == 4 && this.status == 200) {
                console.log(this.responseText);
            }
        };
        xhttp.open("GET", window.location.href + "0b31ddaf-ad52-4e3d-a738-3e34d3b9c093", true);
        xhttp.setRequestHeader("Content-type", "application/json");
        xhttp.send();
    }
</script>
```

The JavaScript code sends a GET request to the current URL with a specific path and logs the response to the console.
We can see that the path is a UUID.

When we send a GET request to the server with the UUID as the path, we get the flag as the response.
We can either manually craft the request or call the JavaScript function in the console of the developer tools to get the flag.
