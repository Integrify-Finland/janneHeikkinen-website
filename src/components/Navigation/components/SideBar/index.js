import React from "react"
import { Link } from "gatsby"
import PropTypes from "prop-types"
import classNames from "classnames"
import "./styles.scss"

const SideBar = ({ show, toggleMenu }) => {
  return (
    <aside>
      <div className={classNames("mobile-menu", { "mobile-menu--open": show })}>
        <div
          className="mobile-menu__close"
          onKeyPress={toggleMenu}
          tabIndex={-1}
          role="button"
          onClick={toggleMenu}
          aria-label="Close"
        />
      

        <div className="mobile-menu__links">
        <Link to="/" className="mobile-menu__nav-link">Etusivu</Link>
          <Link to="/janne" className="mobile-menu__nav-link">Janne</Link>
          <Link
            to="/blogi"
            className="mobile-menu__nav-link"
            activeClassName="mobile-menu__nav-link--active"
          >Blogi</Link>
          <Link
            to="/videot"
            className="mobile-menu__nav-link"
            activeClassName="mobile-menu__nav-link--active"
          >Videot</Link>

          <Link to="/medialle" className="mobile-menu__nav-link">Medialle</Link>

          <Link
            to="/yhteystiedot"
            className="mobile-menu__nav-link"
            activeClassName="mobile-menu__nav-link--active"
          >Yhteystiedot</Link>
        </div>
      </div>
    </aside>
  )
}

SideBar.propTypes = {
  show: PropTypes.bool.isRequired,
  toggleMenu: PropTypes.func.isRequired,
}

export default SideBar
