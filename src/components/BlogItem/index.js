import React from "react"
import "./styles.scss"
import { Link } from "gatsby"
import PropTypes from "prop-types"

import Button from "../Button"
import Img from "gatsby-image"

const BlogItem = ({
  isSidebar,
  isFluid,
  date,
  title,
  number,
  image,
  text,
  link,
  isContentful,
}) => {
  const renderText = () => {
    if (text && isContentful) {
      return <p>{text.substring(0, 450) + "..."}</p>
    } else if (text && !isContentful) {
      return (
        <div
          dangerouslySetInnerHTML={{ __html: text.substring(0, 450) + "..." }}
        />
      )
    } else return "Sorry, no text"
  }

  const content = (
    <div className="blog-item">
      <p className="blog-item__date">{date}</p>
      <p className="blog-item__title">{title}</p>
      <div className="blog-item__number">{number}</div>
      {!isFluid && (
        <div className="blog-item__image">
          <img alt="for blog item" src={image}></img>
        </div>
      )}
      {isFluid && (
        <div className="blog-item__image">
          <Img fluid={image.fluid} className="blog-item__image--fluid"></Img>
        </div>
      )}
      <div className="blog-item__text">
        <p>{renderText()}</p>
        <div className="blog-item__button">
          <Link to={link}>
            <Button variant="secondary" size="sm" label="Lue lisää" />
          </Link>
        </div>
      </div>
    </div>
  )
  const forSidebar = (
    <Link to={link}>
      <div className="blog-item-mini">
        <div className="blog-item-mini__wrapper">
          <p className="blog-item-mini__title">{title}</p>
          <p className="blog-item-mini__date">{date}</p>
        </div>

        {!isFluid && <img alt="for blog item" src={image}></img>}
        {isFluid && (
          <Img
            fluid={image.fluid}
            className="blog-item-mini__image--fluid"
          ></Img>
        )}
      </div>
    </Link>
  )
  return <>{!isSidebar ? content : forSidebar}</>
}

export default BlogItem

BlogItem.propTypes = {
  number: PropTypes.number,
  title: PropTypes.string.isRequired,
  date: PropTypes.func.isRequired,
  link: PropTypes.string.isRequired,
  image: PropTypes.object.isRequired,
}
