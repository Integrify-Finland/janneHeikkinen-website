import PropTypes from "prop-types"
import classNames from "classnames"
import React from "react"
import "./styles.scss"

const AboutTextBlock = ({ title, text, icon, isLeft }) => {
  const classes = classNames({
    iconRight: isLeft,
    iconLeft: !isLeft,
  })

  return (
    <div className="about-text-block">
      <img className={classes} src={icon} alt="icons" />
      <div className="about-text-block__text-wrapper">
        <h1 className="about-text-block__title">
          <u>{title}</u>
        </h1>
        <p className="about-text-block__paragraph">{text}</p>
      </div>
    </div>
  )
}

AboutTextBlock.propTypes = {
  headline: PropTypes.string,
  text: PropTypes.string,
  icon: PropTypes.string,
  isLeft: Boolean,
}

AboutTextBlock.defaultProps = {
  isLeft: false,
}

export default AboutTextBlock
