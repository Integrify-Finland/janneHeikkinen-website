import React from "react"
import Img from "gatsby-image"
import PropTypes from "prop-types"
import { Link } from "gatsby"
import classNames from "classnames"
import defImage from "../../assets/images/thumbnail.jpg"

import {
  FacebookShareButton,
  TwitterShareButton,
  FacebookIcon,
  TwitterIcon,
} from "react-share"

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
  slug,
}) => {
  const shareUrl = "http://www.janneheikkinen.fi/blogi/" + slug

  const prevSlug = allSlugs[allSlugs.indexOf(slug) - 1]
  const nextSlug = allSlugs[allSlugs.indexOf(slug) + 1]
  let isFirst = false
  let isLast = false

  if (!image) image = defImage

  if (!prevSlug) {
    isFirst = true
  }

  if (!nextSlug) {
    isLast = true
  }

  const prevClasses = classNames({
    prevDisplayNone: isFirst,
  })

  const nextClasses = classNames({
    nextDisplayNone: isLast,
  })

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
          <div className="blog-post__share-button-container">
            <FacebookShareButton
              url={shareUrl}
              quote={title}
              className="blog-post__share-button"
            >
              <FacebookIcon size={64} round />
            </FacebookShareButton>

            <TwitterShareButton
              url={shareUrl}
              quote={title}
              className="blog-post__share-button"
            >
              <TwitterIcon size={64} round />
            </TwitterShareButton>
          </div>
        </div>
      </div>
      <div className="blogPost-button-container">
        <Link to={`blogi/${prevSlug}`}>
          <button className={prevClasses}>◀ Edellinen</button>
        </Link>
        <Link to={`blogi/${nextSlug}`}>
          <button className={nextClasses}>Seuraava ▶</button>
        </Link>
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
