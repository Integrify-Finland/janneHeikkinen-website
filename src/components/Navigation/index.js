import React from 'react'
import { Link } from 'gatsby'
import Logo from "./assets/logo.svg"
import FacebookIcon from "../SocialMediaIcons/Facebook/index"
import TwitterIcon from "../SocialMediaIcons/Twitter/index"
import InstagramIcon from "../SocialMediaIcons/Instagram/index"

import './styles.scss'

const Navigation = () => (
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
        to="/yhteystiedot"
        className="navbar__nav-link"
        activeClassName="navbar__nav-link--active"
      >
        Yhteystiedot
      </Link>

      <a
        href="#"
        className="navbar__nav-media-link"
        target="blank"
        rel="noopener"
        title="Go to Facebook"
      >
        <FacebookIcon iconSize="small" />
      </a>

      <a
        href="#"
        className="navbar__nav-media-link"
        target="blank"
        rel="noopener"
        title="Go to Twitter"
      >
        <TwitterIcon iconSize="small" />
      </a>

      <a
        href="#"
        className="navbar__nav-media-link"
        target="blank"
        rel="noopener"
        title="Go to Instagram"
      >
        <InstagramIcon iconSize="small" />
      </a>
      
      
    </div>
   
  </nav>
)


export default Navigation
