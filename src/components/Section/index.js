import * as React from "react"
import classNames from "classnames"
import "./styles.scss"

const Section = ({ children, isBlog }) => {
  const styles = classNames({
    section: true,
    "section--blog-post": isBlog,
  })
  return (
    <section className={styles}>
      {children && <div className="section__children">{children}</div>}
    </section>
  )
}

Section.defaultProps = {
  children: null,
}

export default Section
