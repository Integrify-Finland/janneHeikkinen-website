import React from "react"
import "./styles.scss"
import { Link } from "gatsby"
import PropTypes from "prop-types"
// import formatDate from '../../utilities/FormatDate'
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
}) => {
  const styles = {
    textAlign: "center",
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
        <Img
          fluid={image.fluid}
          style={{ maxWidth: `100%`, width: "300px" }}
        ></Img>
      )}
      <div className="blog-item__text">
        <p>{text}</p>
        <div style={styles}>
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

        <img src={image} alt="for blog post" />
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
  image: PropTypes.string.isRequired,
}
