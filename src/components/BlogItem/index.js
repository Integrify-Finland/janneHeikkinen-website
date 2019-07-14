import React from 'react'
import './styles.scss'
import { Link } from 'gatsby'
import PropTypes from 'prop-types'
// import formatDate from '../../../../utilities/FormatDate'
import Button from '../Button'


<<<<<<< HEAD
const BlogItem = ({ date,  title, number, image, text }) => {
  const content =  
    <div className="blog-item">
=======
const BlogItem = ({ date,  title, number, image, text, link }) => {
  const content =  
    <Link className="blog-item" to={link}>
>>>>>>> 86f5dc44765b9c4c33b752bccaa3b6ec64e987fb
      <p className="blog-item__date">{date}</p>
      <p className="blog-item__title">{title}</p>
      <p className="blog-item__number">{number}</p>
      <img src={image}></img>
      <div className="blog-item__text">
        <p>{text}</p>
<<<<<<< HEAD
        <Button variant="secondary" size="sm" label="Lue lisää" /> 
      </div>
    </div>
=======
        <Button variant="blog" size="sm" label="Read more" /> 
     </div>
    </Link>
>>>>>>> 86f5dc44765b9c4c33b752bccaa3b6ec64e987fb
  

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