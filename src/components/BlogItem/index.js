import React from 'react'
import './styles.scss'
import { Link } from 'gatsby'
import PropTypes from 'prop-types'
// import formatDate from '../../../../utilities/FormatDate'
import Button from '../Button'


const BlogItem = ({ date,  title, number, image, text, link }) => {
  const content =  
    <Link className="blog-item" to={link}>
      <p className="blog-item__date">{date}</p>
      <p className="blog-item__title">{title}</p>
      <p className="blog-item__number">{number}</p>
      <img src={image}></img>
      <div className="blog-item__text">
        <p>{text}</p>
        <Button variant="secondary" size="sm" label="Lue lisää" /> 
     </div>
    </Link>
  

  return (
    <>
        {content}
    </>
  )
}

export default BlogItem

BlogItem.propTypes = {
  number: PropTypes.number,
  title: PropTypes.string.isRequired,
  date: PropTypes.func.isRequired,
  link: PropTypes.string.isRequired,
  image: PropTypes.string.isRequired
}

// BlogItem.defaultProps = {
//   media: null,
//   wrapper: false,
// }