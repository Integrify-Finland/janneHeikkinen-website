import { Link } from "gatsby"
import PropTypes from "prop-types"
import classNames from "classnames"
import React from "react"
import "./styles.scss"

const AboutTextBlock = ({ title, text, icon, isLeft }) => {
  const classes = classNames({
    iconRight: isLeft
})

return (
  <div className="aboutTextBlock">
    <img className={classes} src={icon} />
    <div>
    <h1 className="aboutTextBlock__title"><u>{title}</u></h1>
    <p className="aboutTextBlock__paragraph">{text}</p>
    </div>
  </div>
)}

AboutTextBlock.propTypes = {
  headline: PropTypes.string,
  text: PropTypes.string,
  icon: PropTypes.string,
  isLeft: Boolean,
}

AboutTextBlock.defaultProps = {
  title: `Headline`,
  isLeft: false,
}

export default AboutTextBlock
