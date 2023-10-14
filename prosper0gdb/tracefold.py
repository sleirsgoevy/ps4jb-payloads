import html

print(end='''\
<style>
input {
    display: none;
}

input + label:before {
    content: "+ call";
    color: blue;
}

input:checked + label:before {
    content: "- call";
    color: blue;
}

input + label + div {
    display: none;
}

input:checked + label + div {
    display: block;
    padding-left: 5px;
    border-left: 1px solid black;
}
</style><pre>''')

idx = 0

while True:
    l = input()
    if l.startswith('+ call'):
        print(end='<input type=checkbox id=ck%d /><label for=ck%d>%s</label><div>'%(idx, idx, l[6:]))
        idx += 1
    elif (l+' ').startswith('+ ret '):
        print('+ ret</div>')
    else:
        print(html.escape(l))
