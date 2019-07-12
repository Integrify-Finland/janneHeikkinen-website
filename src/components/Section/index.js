import * as React from "react"

import "./styles.scss"

const Section = ({ children }) => {
  return (
    <section className="section">
      {children && <div className="section__children">{children}</div>}
    </section>
  )
}

Section.defaultProps = {
  children: null,
}

export default Section
