import React from "react"
import { Link } from "gatsby"
import classNames from "classnames"
import PropTypes from "prop-types"
import "./styles.scss"
import janneImage from "./assets/janneHeader.png"
import Navigation from "../Navigation"
import Newsletter from "../Newsletter"

const Header = ({ Headline, Subtext }) => {
  return (
    <div className="header-wrapper">
      <Navigation />
      <header className="header">
        <div className="header__textbox">
          <h1 className="header__headline">{Headline}</h1>
          <p className="header__subtext">{Subtext}</p>
          <div className="header__newsletter-wrapper">
            <Newsletter />
          </div>
        </div>

        <img className="header__image" src={janneImage} />
      </header>
    </div>
  )
}

Header.propTypes = {
  Headline: PropTypes.string,
  Subtext: PropTypes.string,
}

Header.defaultProps = {
  Headline: `Janne Heikkinen`,
  Subtext: `I'm the greatest politician in the world!`,
}

export default Header
