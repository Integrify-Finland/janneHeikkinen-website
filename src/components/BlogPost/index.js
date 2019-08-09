import React from "react"
import './styles.scss'
import PropTypes from "prop-types"

const BlogPost = ({ image, title, date, children}) => {
return (
<div className="blog-post">
    <div className="blog-post__date">{date}</div>
    <div className="blog-post__title">{title}</div>
    <div className="blog-post__image">
        <img src={image}></img>
    </div>
    <div className="blog-post__content">
        {children && <div className="blog-post__content__children">{children}</div>}
    </div>
</div>
)
}

BlogPost.propTypes = {
    title: PropTypes.string.isRequired,
    date: PropTypes.func.isRequired,
    image: PropTypes.string.isRequired,
}

export default BlogPost