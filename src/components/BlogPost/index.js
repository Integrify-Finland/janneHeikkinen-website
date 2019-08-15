import React from "react"
import Img from "gatsby-image"
import PropTypes from "prop-types"
import { Link } from "gatsby"

import { FacebookShareButton, TwitterShareButton, FacebookIcon,
  TwitterIcon, } from "react-share"

import "./styles.scss"


const BlogPost = ({
  isFluid,
  image,
  title,
  date,
  children,
  categories,
  tags,
  allSlugs,
  slug
}) => {

  const shareUrl = "http://www.janneheikkinen.fi/blogi/" + slug;

  /* const findIndex = allSlugs.forEach((slugs, index) => {
    console.log(index)
    console.log(slugs)
    console.log(slug)
    if (slugs == slug) return ("HIERIEIIE")
  } )

  console.log(findIndex) */
console.log(allSlugs[0])
for (let i=0; i++; i < allSlugs.length) {

  console.log(allSlugs[i])
  console.log(slug)
    if (slug === allSlugs[i]) {
      return i;
    }
    console.log(i);
  }





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

    <div className="blog-post__footer">
          <div>
        <div className="blog-post__categories">
          Categories:<span>{categories}</span>
        </div>
        <div className="blog-post__tags">
          Tags:<span>{tags}</span>
        </div>
        </div>
        <div>
        <FacebookShareButton
            url={shareUrl}
            quote={title}
            className="blog-post__share-button">
            <FacebookIcon
              size={64}
              round />
          </FacebookShareButton>

          <TwitterShareButton
            url={shareUrl}
            quote={title}
            className="blog-post__share-button">
            <TwitterIcon
              size={64}
              round />
          </TwitterShareButton>
          </div>
          </div>
      </div>
      <div className="blogPost-button-container">
        <Link to={`blogi/${slug}`}><button>Previous</button></Link>
        <Link to={`yhteys`}><button>Next</button></Link>
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
