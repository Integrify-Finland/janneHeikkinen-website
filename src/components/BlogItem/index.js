import React from "react"
import "./styles.scss"
import { Link } from "gatsby"
import PropTypes from "prop-types"
// import formatDate from '../../utilities/FormatDate'
import Button from "../Button"

const BlogItem = ({ date, title, number, image, text, link }) => {
  const styles = {
    textAlign: "center",
  }

  const content = (
    <div className="blog-item">
      <p className="blog-item__date">{date}</p>
      <p className="blog-item__title">{title}</p>
      <div className="blog-item__number">{number}</div>
      <div className="blog-item__image">
        <img src={image}></img>
      </div>
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

  return <>{content}</>
}

export default BlogItem

BlogItem.propTypes = {
  number: PropTypes.number,
  title: PropTypes.string.isRequired,
  date: PropTypes.func.isRequired,
  link: PropTypes.string.isRequired,
  image: PropTypes.string.isRequired,
}
