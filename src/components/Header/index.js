import React, { useState } from "react"
import { Link } from "gatsby"
import classNames from "classnames"
import PropTypes from "prop-types"
import "./styles.scss"
import janneImage from "./assets/janneHeader.png"
import Navigation from "../Navigation"
import Newsletter from "../Newsletter"

const Header = ({ Headline, Subtext }) => {
  
  const [animationStage, setAnimationStage] = useState("initial")
  
  const textboxClassName = classNames({
    'header__textbox': true,
    'first-stage': animationStage === "first stage",
    'second-stage': animationStage === "second stage",
  });


  const content = (
    <div className="header-wrapper"> 
      <Navigation />
      <header className="header">
        <div className="header__box">
          <div className={textboxClassName}>
            <h1 className="header__headline">{Headline}</h1>
            <p className="header__subtext">{Subtext}</p>
          </div>
          <div className="header__newsletter-wrapper">
        
            <Newsletter
            animationStage={animationStage}
            setAnimationStage={setAnimationStage}
            />

          </div>
        </div>
    
        <img className="header__image" src={janneImage} />
  
      </header>
    </div>)

    return content

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
