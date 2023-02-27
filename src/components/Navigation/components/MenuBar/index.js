import React from "react"
import { Link } from "gatsby"
import Logo from "../assets/logo.svg"
import FacebookIcon from "../../../SocialMediaIcons/Facebook/index"
import TwitterIcon from "../../../SocialMediaIcons/Twitter/index"
import InstagramIcon from "../../../SocialMediaIcons/Instagram/index"

import "./styles.scss"

const MenuBar = ({ toggleMenu }) => (
  <div className="navbar__wrapper">
    <nav className="navbar">
      <div className="navbar__logo">
        <Link to="/">
          <img src={Logo} alt="Janne Heikkinen logo" />
        </Link>
      </div>

      <div className="navbar__links">
        <Link
          to="/"
          className="navbar__nav-link"
          activeClassName="navbar__nav-link--active"
        >
          Etusivu
        </Link>

        <Link
          to="/janne"
          className="navbar__nav-link"
          activeClassName="navbar__nav-link--active"
        >
          Janne
        </Link>

        <Link
          to="/vaalit"
          className="navbar__nav-link"
          activeClassName="navbar__nav-link--active"
        >
          Vaalit
        </Link>
        <Link
          to="/blogi"
          className="navbar__nav-link"
          activeClassName="navbar__nav-link--active"
        >
          Blogi
        </Link>

        <Link
          to="/videot"
          className="navbar__nav-link"
          activeClassName="navbar__nav-link--active"
        >
          Videot
        </Link>

        <Link
          to="/medialle"
          className="navbar__nav-link"
          activeClassName="navbar__nav-link--active"
        >
          Medialle
        </Link>
        <Link
          to="/osallistu"
          className="navbar__nav-link"
          activeClassName="navbar__nav-link--active"
        >
          Osallistu
        </Link>

        <Link
          to="/yhteys"
          className="navbar__nav-link"
          activeClassName="navbar__nav-link--active"
        >
          Yhteystiedot
        </Link>
      </div>
      <div className="navbar__links">
        <a
          href="https://www.facebook.com/janneheikkinenpage/"
          className="navbar__nav-media-link"
          target="blank"
          rel="noopener"
          title="Go to Facebook"
        >
          <FacebookIcon iconSize="small" />
        </a>

        <a
          href="https://twitter.com/heikkinenjanne"
          className="navbar__nav-media-link"
          target="blank"
          rel="noopener"
          title="Go to Twitter"
        >
          <TwitterIcon iconSize="small" />
        </a>

        <a
          href="https://www.instagram.com/janneheikkinen/"
          className="navbar__nav-media-link"
          target="blank"
          rel="noopener"
          title="Go to Instagram"
        >
          <InstagramIcon iconSize="small" />
        </a>
      </div>

      <div
        role="button"
        onKeyPress={toggleMenu}
        onClick={toggleMenu}
        className="mobile-menu__button navbar__menu"
        tabIndex="-1"
        aria-label="Close"
      >
        &#9776;
      </div>
    </nav>
  </div>
)

export default MenuBar
