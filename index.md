Here are my latest blog posts:

- [Post 1](./_posts/post1.md)
- [Post 2](./_posts/post2.md)
- [Post 3](./_posts/post3.md)

## Blog

{% for post in site.posts %}
### [{{ post.title }}]({{ post.url }})
{{ post.excerpt }}  
[Read More]({{ post.url }})
---
{% endfor %}