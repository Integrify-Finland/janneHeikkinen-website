import React, { useState } from "react"

import classNames from "classnames"
import PropTypes from "prop-types"
import "./styles.scss"
import janneImage from "./assets/janneHeader.png"
import Logo from "./assets/logo.svg"

import Newsletter from "../Newsletter"

const Header = ({
  Headline,
  Subtext,
  isAbout,
  Kotipaikka,
  Syntynyt,
  Perhe,
  Sotilasarvo_aselinja,
  Ammatti,
  Harrastukset,
  Koulutus,
  Luottamustehtava,
}) => {
  const [animationStage, setAnimationStage] = useState("initial")

  const textboxClassName = classNames({
    header__textbox: true,
    "first-stage": animationStage === "first stage",
    "second-stage": animationStage === "second stage",
  })

  if (!isAbout) {
    return (
      <div className="header-wrapper">
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

          <img
            alt="Janne Heikkinen"
            className="header__image"
            src={janneImage}
          />
        </header>
      </div>
    )
  } else
    return (
      <div className="about-header-wrapper">
        <header className="about-header">
          <div className="about-header__textbox">
            <img src={Logo} alt="Janne Heikkinen logo" />
            <h3>Kotipaikka:</h3>
            <p>{Kotipaikka}</p>

            <h3>Syntynyt:</h3>
            <p>{Syntynyt}</p>

            <h3>Perhe:</h3>
            <p>{Perhe}</p>

            <h3>Sotilasarvo ja aselinja:</h3>
            <p>{Sotilasarvo_aselinja}</p>

            <h3>Ammatti:</h3>
            <p>{Ammatti}</p>

            <h3>Harrastukset:</h3>
            <p>{Harrastukset}</p>

            <h3>Koulutus:</h3>
            <p>{Koulutus}</p>

            <h3>Nykyinen luottamustehtävä:</h3>
            <p>{Luottamustehtava}</p>
          </div>
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
