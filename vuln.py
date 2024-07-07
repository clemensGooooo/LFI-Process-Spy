# Example vulnerable server

from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <h1>Welcome to the LFI Vulnerable App</h1>
    <form action="/view" method="get">
        <label for="file">Enter file name:</label>
        <input type="text" id="file" name="file">
        <input type="submit" value="View File">
    </form>
    '''

@app.route('/view')
def view_file():
    file = request.args.get('file')
    if file:
        try:
            with open(file, 'r') as f:
                content = f.read()
            return render_template_string('<pre>{{ content }}</pre>', content=content)
        except Exception as e:
            return str(e)
    return "No file specified!"

if __name__ == '__main__':
    app.run(debug=True)
