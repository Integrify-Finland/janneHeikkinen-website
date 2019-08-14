import React from "react"
import Img from "gatsby-image"
import PropTypes from "prop-types"

import "./styles.scss"
const BlogPost = ({ isFluid, image, title, date, children }) => {
  return (
    <div className="blog-post">
      <div className="blog-post__date">{date}</div>
      <div className="blog-post__title">{title}</div>
      <div className="blog-post__image">
        {!isFluid && <img alt="blog entry" src={image}></img>}
        {isFluid && (
          <div className="blog-item__image">
            <Img fluid={image.fluid} className="blog-item__image--fluid"></Img>
          </div>
        )}
      </div>
      <div className="blog-post__content">
        {children && (
          <div className="blog-post__content__children">{children}</div>
        )}
      </div>
    </div>
  )
}

BlogPost.propTypes = {
  title: PropTypes.string.isRequired,
  date: PropTypes.string.isRequired,
  image: PropTypes.string.isRequired,
}

export default BlogPost
