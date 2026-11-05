import React from "react"
import PropTypes from "prop-types"

import "./styles.scss"

// Cleans up editor input: splits anything typed as "A, B" into separate
// names, trims spaces and drops empty and duplicate entries
const cleanNames = list =>
  Array.from(
    new Set(
      (list || [])
        .reduce((all, item) => all.concat((item || "").split(",")), [])
        .map(name => name.trim().replace(/\s+/g, " "))
        .filter(Boolean)
    )
  )

// Each half of the moving track has to be wider than the widest screen,
// otherwise the end of the list shows up as empty space before the loop
// restarts. Short lists are repeated until a half has at least this many tags.
const MIN_TAGS_PER_HALF = 40
const SECONDS_PER_TAG = 3

const MunicipalityCarousel = ({ names: rawNames }) => {
  const names = cleanNames(rawNames)
  if (names.length === 0) return null

  const repeat = Math.ceil(MIN_TAGS_PER_HALF / names.length)
  const half = Array.from({ length: repeat }).reduce(all => all.concat(names), [])
  // Same speed however long the list is
  const duration = `${half.length * SECONDS_PER_TAG}s`

  const renderHalf = key => (
    <ul className="municipality-carousel__list" key={key}>
      {half.map((name, i) => (
        <li className="municipality-carousel__item" key={i}>
          {name}
        </li>
      ))}
    </ul>
  )

  return (
    <div className="municipality-carousel">
      {/* Plain list read by screen readers, and shown as a still row
          for visitors who prefer reduced motion */}
      <ul className="municipality-carousel__static">
        {names.map(name => (
          <li className="municipality-carousel__item" key={name}>
            {name}
          </li>
        ))}
      </ul>
      {/* Two identical halves: moving by exactly one half makes the loop seamless */}
      <div
        className="municipality-carousel__track"
        style={{ animationDuration: duration }}
        aria-hidden="true"
      >
        {renderHalf("a")}
        {renderHalf("b")}
      </div>
    </div>
  )
}

MunicipalityCarousel.propTypes = {
  names: PropTypes.arrayOf(PropTypes.string),
}

export default MunicipalityCarousel
