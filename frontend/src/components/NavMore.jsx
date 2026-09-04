import { useState, useRef, useEffect } from "react";
import { Link } from "react-router-dom";

export default function NavMore({ items }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    function handleClick(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  const visibleItems = items.filter((i) => i.show);
  if (visibleItems.length === 0) return null;

  return (
    <div className="nav-more" ref={ref}>
      <button className="nav-more-btn" onClick={() => setOpen((o) => !o)}>
        More ▾
      </button>
      {open && (
        <div className="nav-more-dropdown">
          {visibleItems.map((i) => (
            <Link key={i.to} to={i.to} onClick={() => setOpen(false)}>
              {i.label}
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}