---
layout: default
title: "Blog"
---

## Blog

{% for post in paginator.posts %}
### [{{ post.title }}]({{ post.url }})
{{ post.excerpt | strip_html }}  
[Read More]({{ post.url }})
---
{% endfor %}