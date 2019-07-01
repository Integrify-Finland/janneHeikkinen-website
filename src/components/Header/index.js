import { Link } from "gatsby"
import PropTypes from "prop-types"
import React from "react"
import "./styles.scss"

const Header = ({ siteTitle }) => (
  <header className="header">
    <h1 className="header__title">
      <Link to="/">{siteTitle}</Link>
    </h1>
  </header>
)

Header.propTypes = {
  siteTitle: PropTypes.string,
}

Header.defaultProps = {
  siteTitle: ``,
}

export default Header
