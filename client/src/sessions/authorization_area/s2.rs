use crate::sessions::{
    AuthorizationArea, AuthorizationArea1Plus, AuthorizationArea2Plus, NoSession, Session,
};

impl<T: Session, U: Session> AuthorizationArea<T, U, NoSession> for (T, U) {
    fn decompose_ref(&self) -> (Option<&T>, Option<&U>, Option<&NoSession>) {
        (Some(&self.0), Some(&self.1), None)
    }
    fn decompose_mut(&mut self) -> (Option<&mut T>, Option<&mut U>, Option<&mut NoSession>) {
        (Some(&mut self.0), Some(&mut self.1), None)
    }
}

impl<T: Session, U: Session> AuthorizationArea1Plus<T, U, NoSession> for (T, U) {
    fn decompose_ref(&self) -> (&T, Option<&U>, Option<&NoSession>) {
        (&self.0, Some(&self.1), None)
    }
    fn decompose_mut(&mut self) -> (&mut T, Option<&mut U>, Option<&mut NoSession>) {
        (&mut self.0, Some(&mut self.1), None)
    }
}

impl<T: Session, U: Session> AuthorizationArea2Plus<T, U, NoSession> for (T, U) {
    fn decompose_ref(&self) -> (&T, &U, Option<&NoSession>) {
        (&self.0, &self.1, None)
    }
    fn decompose_mut(&mut self) -> (&mut T, &mut U, Option<&mut NoSession>) {
        (&mut self.0, &mut self.1, None)
    }
}
