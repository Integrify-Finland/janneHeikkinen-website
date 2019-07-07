import { Link } from "gatsby"
import classNames from "classnames"
import PropTypes from "prop-types"
import React from "react"
import "./styles.scss"

const Header = ({ siteTitle, isGreen }) => {
  const classes = classNames({
    header__title: true,
    header__green: isGreen,
  })
  return (
    <header className="header">
      <h1 className={classes}>
        <Link to="/">{siteTitle}</Link>
      </h1>
    </header>
  )
}

Header.propTypes = {
  siteTitle: PropTypes.string,
}

Header.defaultProps = {
  siteTitle: ``,
}

export default Header
